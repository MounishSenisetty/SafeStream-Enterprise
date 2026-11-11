"""Broker-level tests: the connector against a real Kafka.

Skipped unless ``SAFESTREAM_IT_BOOTSTRAP`` names a broker (CI starts one as a
service container). ``SAFESTREAM_IT_IMAGE`` additionally runs the built Docker
image with the same restrictions the Kubernetes manifest applies.
"""

from __future__ import annotations

import json
import os
import random
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from confluent_kafka import Consumer, KafkaException, Message, Producer, TopicPartition
from confluent_kafka.admin import (
    AdminClient,
    AlterConfigOpType,
    ConfigEntry,
    ConfigResource,
    NewTopic,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safestream_enterprise import DEFAULT_FIELD_RULES, dlq, policy
from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    KafkaRedactionConnector,
    build_redactor,
    load_policy,
)

BOOTSTRAP = os.environ.get("SAFESTREAM_IT_BOOTSTRAP", "")
IMAGE = os.environ.get("SAFESTREAM_IT_IMAGE", "")
#: Docker container running the broker, so a test can kill and restart it.
KAFKA_CONTAINER = os.environ.get("SAFESTREAM_IT_KAFKA_CONTAINER", "")
pytestmark = pytest.mark.skipif(not BOOTSTRAP, reason="SAFESTREAM_IT_BOOTSTRAP not set")

PII_RECORD = {"LastName": "Smith", "password": "hunter2", "msg": "mail bob@corp.example"}


@pytest.fixture
def topics() -> Iterator[dict[str, str]]:
    """Fresh single-partition topics per test, so runs never see each other's data."""
    suffix = uuid.uuid4().hex[:8]
    names = {k: f"it-{k}-{suffix}" for k in ("ingress", "egress", "dlq", "audit")}
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    new = [NewTopic(t, num_partitions=1, replication_factor=1) for t in names.values()]
    for future in admin.create_topics(new).values():
        future.result(30)
    yield names
    admin.delete_topics(list(names.values()))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def http_get(port: int, path: str) -> tuple[int, str]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # loopback
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def produce(topic: str, records: list[tuple[bytes | None, bytes | None]], **kw: object) -> None:
    p = Producer({"bootstrap.servers": BOOTSTRAP})
    for key, value in records:
        p.produce(topic, key=key, value=value, **kw)  # type: ignore[arg-type]
    assert p.flush(30) == 0


def drain(topic: str, expected: int, timeout_s: float = 60.0) -> list[Message]:
    """Read ``topic`` from the start until ``expected`` records arrive (or time out)."""
    c = Consumer(
        {
            "bootstrap.servers": BOOTSTRAP,
            "group.id": f"it-reader-{uuid.uuid4().hex}",
            "auto.offset.reset": "earliest",
            "enable.auto.commit": False,
            # What a downstream consumer must use for the exactly_once guarantee;
            # also correct for at_least_once (no transactions -> nothing hidden).
            "isolation.level": "read_committed",
        }
    )
    c.subscribe([topic])
    out: list[Message] = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected and time.monotonic() < deadline:
        msg = c.poll(0.5)
        if msg is not None and msg.error() is None:
            out.append(msg)
    # Linger briefly: catches *extra* records (duplicates) beyond the expected count.
    end = time.monotonic() + 2
    while time.monotonic() < end:
        msg = c.poll(0.2)
        if msg is not None and msg.error() is None:
            out.append(msg)
    c.close()
    return out


def committed_lag(group: str, topic: str) -> int:
    """Records in ``topic`` not yet covered by ``group``'s committed offset."""
    c = Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": group})
    (tp,) = c.committed([TopicPartition(topic, 0)], timeout=10)
    _, high = c.get_watermark_offsets(tp, timeout=10)
    c.close()
    return high - max(tp.offset, 0)


class Running:
    """The connector on a background thread, stopped (gracefully) on exit."""

    def __init__(self, config: ConnectorConfig) -> None:
        self.connector = KafkaRedactionConnector(
            config,
            build_redactor(config),
            Consumer(config.consumer_config()),
            Producer(config.producer_config()),
        )
        self.errors: list[BaseException] = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        try:
            self.connector.run()
        except BaseException as exc:
            self.errors.append(exc)

    def __enter__(self) -> KafkaRedactionConnector:
        self.thread.start()
        return self.connector

    def __exit__(self, *_exc: object) -> None:
        self.connector.stop()
        self.thread.join(30)
        assert not self.thread.is_alive(), "connector did not stop within 30s"
        assert not self.errors, self.errors


@pytest.mark.parametrize("delivery", ["at_least_once", "exactly_once"])
def test_end_to_end_redaction_dlq_commit_and_resume(topics: dict[str, str], delivery: str) -> None:
    group = f"it-connector-{uuid.uuid4().hex[:8]}"
    config = ConnectorConfig(
        bootstrap_servers=BOOTSTRAP,
        group_id=group,
        ingress_topic=topics["ingress"],
        egress_topic=topics["egress"],
        dlq_topic=topics["dlq"],
        audit_topic=topics["audit"],
        poll_timeout_s=0.5,
        delivery=delivery,  # type: ignore[arg-type]
    )
    produce(
        topics["ingress"],
        [
            (b"bob@corp.example", json.dumps(PII_RECORD).encode()),
            (None, b"plain text, not json: alice@corp.example"),
            (b"user-42", None),  # tombstone
            (None, b'<Event><Data Name="TargetUserName">bob</Data><Phone>555 0100</Phone></Event>'),
        ],
        headers=[("fwd", b"token for bob@corp.example")],
    )

    with Running(config) as connector:
        egress = drain(topics["egress"], 3)
        dlq = drain(topics["dlq"], 1)
        # /metrics view of the same run: JSON record, tombstone and XML record
        # to egress, the unparseable record to the DLQ, no aborted transactions
        m = connector.snapshot()
        assert (m.egress_records, m.dlq_records, m.transaction_aborts) == (3, 1, 0)
        assert m.ready and m.batches >= 1 and m.redactions["person"] >= 1

    # Clean topic: JSON record redacted structurally; key and header redacted too.
    assert len(egress) == 3, [m.value() for m in egress]
    record, tombstone, xml_record = egress
    assert json.loads(record.value()) == {
        "LastName": "[REDACTED]",
        "password": "[REDACTED]",
        "msg": "mail [REDACTED]",
    }
    assert record.key() == b"[REDACTED]"
    headers = dict(record.headers() or [])
    assert headers == {"fwd": b"token for [REDACTED]", "x-safestream-redaction": b"structural"}
    assert tombstone.value() is None and tombstone.key() == b"user-42"
    # XML is redacted structurally too, on the same field rules.
    assert xml_record.value() == (
        b'<Event><Data Name="TargetUserName">[REDACTED]</Data><Phone>[REDACTED]</Phone></Event>'
    )
    assert dict(xml_record.headers() or [])["x-safestream-redaction"] == b"structural"

    # DLQ: the unparseable record, untouched, tagged with the exception class only.
    assert len(dlq) == 1
    assert dlq[0].value() == b"plain text, not json: alice@corp.example"
    assert dict(dlq[0].headers() or [])["x-safestream-error"] == b"StructuredParseError"

    # Offsets were committed only after egress acknowledged: nothing left to replay.
    assert committed_lag(group, topics["ingress"]) == 0

    # A restarted connector in the same group resumes after the committed offset:
    # the new record is processed and nothing earlier is replayed.
    produce(topics["ingress"], [(None, b'{"email": "carol@corp.example"}')])
    with Running(config):
        egress = drain(topics["egress"], 4)
    assert len(egress) == 4, "earlier records were replayed or the new one was lost"
    assert json.loads(egress[3].value()) == {"email": "[REDACTED]"}
    assert committed_lag(group, topics["ingress"]) == 0

    # Compliance audit: each run closed its window on shutdown, and the events
    # account for exactly what was processed (3 + 1 egress, 1 DLQ), no more.
    events = [json.loads(m.value()) for m in drain(topics["audit"], 2)]
    assert len(events) == 2 and all(e["window"]["final"] for e in events)
    assert all(e["schema"] == "safestream.audit/v1" and e["delivery"] == delivery for e in events)
    assert sum(e["records"]["egress"] for e in events) == 4
    assert sum(e["records"]["dlq"] for e in events) == 1
    assert sum(e["redactions"].get("email", 0) for e in events) >= 1


@pytest.mark.parametrize("delivery", ["at_least_once", "exactly_once"])
def test_record_the_egress_topic_rejects_is_dead_lettered(
    topics: dict[str, str], delivery: str
) -> None:
    """A record too large for the clean topic must not crash-loop the connector."""
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    limit = ConfigEntry("max.message.bytes", "20000", incremental_operation=AlterConfigOpType.SET)
    resource = ConfigResource(
        ConfigResource.Type.TOPIC, topics["egress"], incremental_configs=[limit]
    )
    for future in admin.incremental_alter_configs([resource]).values():
        future.result(30)
    # Random short words: nothing to redact, and too little repetition for zstd
    # to shrink the record under the topic limit.
    rng = random.Random(7)
    words = ["".join(rng.choices("abcdefghijklmnopqrstuvwxyz", k=4)) for _ in range(40_000)]
    big = json.dumps({"id": "big", "note": " ".join(words)}).encode()
    group = f"it-connector-{uuid.uuid4().hex[:8]}"
    config = ConnectorConfig(
        bootstrap_servers=BOOTSTRAP,
        group_id=group,
        ingress_topic=topics["ingress"],
        egress_topic=topics["egress"],
        dlq_topic=topics["dlq"],
        delivery=delivery,  # type: ignore[arg-type]
        metrics_port=0,
    )
    with Running(config):
        # Separate batches: the broker's limit applies to a whole produce batch,
        # so a record sent together with the big one would be rejected with it.
        produce(topics["ingress"], [(b"k1", json.dumps(PII_RECORD).encode())])
        clean = drain(topics["egress"], expected=1)
        produce(topics["ingress"], [(b"k2", big)])
        dead = drain(topics["dlq"], expected=1)
        produce(topics["ingress"], [(b"k3", json.dumps(PII_RECORD).encode())])
        clean = drain(topics["egress"], expected=2)

    assert [m.key() for m in clean] == [b"k1", b"k3"]
    assert [m.value() for m in dead] == [big]  # the original, for replay after a fix
    assert dict(dead[0].headers() or [])["x-safestream-error"] == b"MSG_SIZE_TOO_LARGE"
    assert committed_lag(group, topics["ingress"]) == 0


def test_dlq_summary_and_replay_through_redaction(topics: dict[str, str]) -> None:
    group = f"it-connector-{uuid.uuid4().hex[:8]}"

    def config(unparseable: str) -> ConnectorConfig:
        return ConnectorConfig(
            bootstrap_servers=BOOTSTRAP,
            group_id=group,
            ingress_topic=topics["ingress"],
            egress_topic=topics["egress"],
            dlq_topic=topics["dlq"],
            delivery="exactly_once",  # DLQ records sit behind transaction markers
            unparseable=unparseable,  # type: ignore[arg-type]
            poll_timeout_s=0.5,
            metrics_port=0,
        )

    def dlq_tool(replay: bool, replay_group: str = "a", **kw: object) -> dict[str, object]:
        cfg = config("dlq")
        consumer = Consumer(dlq.consumer_config(cfg, f"{group}-replay-{replay_group}"))
        producer = Producer({"bootstrap.servers": BOOTSTRAP}) if replay else None
        try:
            return dlq.run(cfg, consumer, producer, **kw)  # type: ignore[arg-type]
        finally:
            consumer.close()

    text = [b"not json: mail alice@corp.example", b"not json: mail carol@corp.example"]
    with Running(config("dlq")):
        produce(topics["ingress"], [(b"k", v) for v in text])
        assert len(drain(topics["dlq"], expected=2)) == 2

    assert dlq_tool(replay=False) == {
        "topic": topics["dlq"],
        "records": 2,
        "by_error": {"StructuredParseError": 2},
    }
    # A filter that matches nothing replays nothing (and, for this group, passes over both).
    assert dlq_tool(replay=True, error="MSG_SIZE_TOO_LARGE", limit=None)["replayed"] == 0

    # "Fix the cause" (accept free text), then replay under a fresh replay group.
    with Running(config("redact_text")):
        first = dlq_tool(replay=True, replay_group="b")
        assert (first["replayed"], first["skipped"]) == (2, 0)
        clean = drain(topics["egress"], expected=2)
    assert sorted(m.value() or b"" for m in clean) == [
        b"not json: mail [REDACTED]",
        b"not json: mail [REDACTED]",
    ]
    # No error tag carried back in, and a second run has nothing left to do.
    assert all("x-safestream-error" not in dict(m.headers() or []) for m in clean)
    assert dlq_tool(replay=True, replay_group="b")["replayed"] == 0


def test_policy_is_swapped_under_load_without_a_restart(
    topics: dict[str, str], tmp_path: Path
) -> None:
    key, intruder = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    path = tmp_path / "policy.json"

    def publish(version: int, rules: dict[str, str], signer: Ed25519PrivateKey = key) -> None:
        # Write-then-rename, as a ConfigMap volume update does: never a half-written file.
        staged = tmp_path / "policy.next"
        staged.write_bytes(policy.sign({"rules": rules}, signer, "acme", version))
        staged.replace(path)

    publish(1, {})
    config = ConnectorConfig(
        bootstrap_servers=BOOTSTRAP,
        group_id=f"it-connector-{uuid.uuid4().hex[:8]}",
        ingress_topic=topics["ingress"],
        egress_topic=topics["egress"],
        dlq_topic=topics["dlq"],
        audit_topic=topics["audit"],
        delivery="exactly_once",
        policy_file=path,
        policy_public_keys=policy.encode_public_key(key.public_key()),
        policy_tenant="acme",
        policy_reload_s=0.2,
        poll_timeout_s=0.2,
        metrics_port=0,
    )
    source, verified = load_policy(config)
    connector = KafkaRedactionConnector(
        config,
        build_redactor(config, verified),
        Consumer(config.consumer_config()),
        Producer(config.producer_config()),
        source,
        verified,
    )
    stop = threading.Event()

    def traffic() -> None:  # steady load for the whole test
        p = Producer({"bootstrap.servers": BOOTSTRAP})
        while not stop.is_set():
            p.produce(topics["ingress"], b'{"loyalty_number":"L-4242-77"}')
            p.poll(0.01)
        p.flush(30)

    def wait_for(condition: Callable[[], bool], what: str) -> None:
        deadline = time.monotonic() + 60
        while not condition():
            assert time.monotonic() < deadline, f"timed out waiting for {what}"
            time.sleep(0.05)

    runner = threading.Thread(target=connector.run, daemon=True)
    feeder = threading.Thread(target=traffic, daemon=True)
    runner.start()
    feeder.start()
    try:
        wait_for(lambda: connector.egress_records > 50, "records under version 1")
        publish(2, {"*loyalty_number*": "id_number"})
        wait_for(lambda: connector.snapshot().policy_version == 2, "version 2 to take effect")
        mark = connector.egress_records
        # An attacker with write access to the file, but not the signing key,
        # tries to switch the rule back off; then replays the old signed bundle.
        publish(3, {}, signer=intruder)
        wait_for(lambda: connector.policy_rejections >= 1, "the forged bundle to be refused")
        publish(1, {})
        wait_for(lambda: connector.policy_rejections >= 2, "the rollback to be refused")
        wait_for(lambda: connector.egress_records > mark + 50, "records after the refusals")
    finally:
        stop.set()
        feeder.join(60)
        connector.stop()
        runner.join(60)
    assert not runner.is_alive()

    values = [m.value() for m in drain(topics["egress"], connector.egress_records)]
    raw, clean = b'{"loyalty_number":"L-4242-77"}', b'{"loyalty_number":"[REDACTED]"}'
    assert set(values) == {raw, clean}
    # One switch, at one point: unredacted only before it, redacted ever after,
    # through the forged bundle and the rollback attempt.
    switch = values.index(clean)
    assert set(values[:switch]) == {raw} and set(values[switch:]) == {clean}
    assert connector.policy is not None and connector.policy.version == 2
    # Each audit event covers one policy; the swap closed the version-1 window.
    audits = [json.loads(m.value() or b"{}") for m in drain(topics["audit"], 2, timeout_s=10)]
    assert [a["policy"]["version"] for a in audits][:2] == [1, 2]
    assert "id_number" not in audits[0]["redactions"] and audits[1]["redactions"]["id_number"] > 0


@pytest.mark.skipif(not KAFKA_CONTAINER, reason="SAFESTREAM_IT_KAFKA_CONTAINER not set")
@pytest.mark.parametrize("delivery", ["at_least_once", "exactly_once"])
def test_broker_killed_mid_stream_loses_nothing(topics: dict[str, str], delivery: str) -> None:
    """Kill the broker under load and run the real connector process, restarted
    whenever it exits, as Kubernetes would. Every record must arrive, and in
    exactly_once only once.

    The process may exit on a Kafka error (1) or because the watchdog found it
    stalled in a client call that never returned (3): both are recoverable."""
    n = 20_000
    produce(
        topics["ingress"],
        [(None, json.dumps({"id": i, "email": "bob@corp.example"}).encode()) for i in range(n)],
    )
    group = f"it-connector-{uuid.uuid4().hex[:8]}"
    env = {
        **os.environ,
        "KAFKA_BOOTSTRAP_SERVERS": BOOTSTRAP,
        "KAFKA_GROUP_ID": group,
        "INGRESS_TOPIC": topics["ingress"],
        "EGRESS_TOPIC": topics["egress"],
        "DLQ_TOPIC": topics["dlq"],
        "SAFESTREAM_DELIVERY": delivery,
        "SAFESTREAM_BATCH_SIZE": "50",
        "SAFESTREAM_FLUSH_TIMEOUT_S": "10",
        "SAFESTREAM_LIVENESS_TIMEOUT_S": "30",
        "SAFESTREAM_METRICS_PORT": "0",
    }
    probe = Consumer({"bootstrap.servers": BOOTSTRAP, "group.id": f"it-probe-{group}"})

    def published() -> int:
        try:
            return probe.get_watermark_offsets(TopicPartition(topics["egress"], 0), timeout=5)[1]
        except KafkaException:
            return 0

    def lag() -> int:
        try:
            return committed_lag(group, topics["ingress"])
        except KafkaException:
            return n  # broker down: nothing is known to be committed

    def start() -> subprocess.Popen[bytes]:
        return subprocess.Popen(
            [sys.executable, "-m", "safestream_enterprise.connectors.kafka"],
            env=env,
            stderr=subprocess.DEVNULL,
        )

    exits: list[int] = []
    process = start()
    try:
        while published() < 2_000:
            assert process.poll() is None, "connector exited before the broker was killed"
            time.sleep(0.05)
        # SIGKILL, mid-batch: no clean shutdown, open transactions left behind.
        subprocess.run(["docker", "kill", KAFKA_CONTAINER], check=True, capture_output=True)
        time.sleep(3)
        subprocess.run(["docker", "start", KAFKA_CONTAINER], check=True, capture_output=True)

        deadline = time.monotonic() + 300
        while lag() > 0:
            assert time.monotonic() < deadline, f"never caught up; exit codes so far: {exits}"
            code = process.poll()
            if code is not None:
                exits.append(code)
                process = start()
            time.sleep(1)
        process.terminate()  # SIGTERM: drain and exit 0
        assert process.wait(60) == 0
    finally:
        process.kill()
        probe.close()

    assert set(exits) <= {1, 3}, exits
    ids = sorted(json.loads(m.value() or b"{}")["id"] for m in drain(topics["egress"], expected=n))
    if delivery == "exactly_once":
        assert ids == list(range(n))  # nothing lost, nothing duplicated
    else:
        assert set(ids) == set(range(n))  # nothing lost; replays may duplicate
    assert drain(topics["dlq"], expected=0, timeout_s=1) == []
    print(f"{delivery}: connector exit codes={exits}, duplicates={len(ids) - n}")


@pytest.mark.skipif(not IMAGE, reason="SAFESTREAM_IT_IMAGE not set")
def test_container_image_under_kubernetes_restrictions(
    topics: dict[str, str], tmp_path: Path
) -> None:
    """The distroless image, read-only, all capabilities dropped, non-root,
    with customer field rules mounted read-only as a ConfigMap would be."""
    name = f"it-{uuid.uuid4().hex[:8]}"
    rules = tmp_path / "field-rules.json"
    rules.write_text(json.dumps({"rules": {"*loyalty_number*": "id_number"}}), encoding="utf-8")
    rules.chmod(0o644)  # readable by the image's non-root user
    metrics_port = free_port()
    env = {
        "KAFKA_BOOTSTRAP_SERVERS": BOOTSTRAP,
        "KAFKA_GROUP_ID": name,
        "INGRESS_TOPIC": topics["ingress"],
        "EGRESS_TOPIC": topics["egress"],
        "DLQ_TOPIC": topics["dlq"],
        "SAFESTREAM_AUDIT_TOPIC": topics["audit"],
        "SAFESTREAM_MODE": "pseudonymize",
        "SAFESTREAM_HMAC_KEY": "ci-only-key-" + "x" * 32,
        # transactional.id derived from the container hostname, as on Kubernetes
        "SAFESTREAM_DELIVERY": "exactly_once",
        "SAFESTREAM_FIELD_RULES_FILE": "/etc/safestream/field-rules.json",
        "SAFESTREAM_METRICS_PORT": str(metrics_port),
    }
    run = ["docker", "run", "-d", "--name", name, "--network", "host", "--read-only"]
    run += ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532"]
    run += ["-v", f"{rules}:/etc/safestream/field-rules.json:ro"]
    for k, v in env.items():
        run += ["-e", f"{k}={v}"]
    subprocess.run([*run, IMAGE], check=True, capture_output=True)
    try:
        record = {**PII_RECORD, "loyaltyNumber": "L-4242-77"}
        produce(topics["ingress"], [(None, json.dumps(record).encode())])
        egress = drain(topics["egress"], 1, timeout_s=90)
        assert len(egress) == 1
        out = json.loads(egress[0].value())
        assert out["LastName"].startswith("<PERSON_") and out["password"].startswith("<SECRET_")
        # the mounted customer rule applied; it is not a built-in rule
        assert out["loyaltyNumber"].startswith("<ID_NUMBER_")

        # probes and metrics, as kubelet and Prometheus would read them
        assert http_get(metrics_port, "/healthz") == (200, "ok\n")
        assert http_get(metrics_port, "/readyz") == (200, "ready\n")
        status, metrics = http_get(metrics_port, "/metrics")
        assert status == 200
        assert 'safestream_records_total{destination="egress"} 1' in metrics
        assert 'safestream_redactions_total{entity_type="id_number"} 1' in metrics
        assert "L-4242-77" not in metrics and "Smith" not in metrics
        assert "Smith" not in egress[0].value().decode()

        # SIGTERM (what Kubernetes sends) drains and exits 0.
        subprocess.run(["docker", "stop", "-t", "30", name], check=True, capture_output=True)
        code = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.ExitCode}}", name],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        assert code == "0", logs.stdout + logs.stderr
        # The SIGTERM drain closed the audit window: one event, content-free.
        (audit,) = [json.loads(m.value()) for m in drain(topics["audit"], 1)]
        assert audit["window"]["final"] and audit["records"] == {"egress": 1, "dlq": 0}
        assert audit["redactions"]["id_number"] == 1  # the mounted custom rule
        assert audit["field_rules"]["count"] == len(DEFAULT_FIELD_RULES) + 1  # + 1 custom
        assert "L-4242-77" not in json.dumps(audit) and "Smith" not in json.dumps(audit)
        # Operational logs never carry record content or secrets.
        for leaked in (
            "Smith",
            "hunter2",
            "bob@corp.example",
            "L-4242-77",
            env["SAFESTREAM_HMAC_KEY"],
        ):
            assert leaked not in logs.stdout + logs.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.mark.skipif(not IMAGE, reason="SAFESTREAM_IT_IMAGE not set")
def test_container_batch_job_over_a_pipe() -> None:
    """``safestream-batch`` inside the distroless image, as the README runs it."""
    cmd = ["docker", "run", "-i", "--rm", "--read-only", "--cap-drop", "ALL"]
    cmd += ["--security-opt", "no-new-privileges", "--user", "65532:65532", "--network", "none"]
    cmd += ["--entrypoint", "/usr/bin/python3", IMAGE, "-m", "safestream_enterprise.batch", "-"]
    record = b'{"LastName":"Smith","msg":"mail bob@corp.example"}\n'
    proc = subprocess.run(
        cmd,
        input=record + b"<u><Phone>555 0100</Phone></u>\n",
        capture_output=True,
        check=True,
    )
    assert proc.stdout == (
        b'{"LastName":"[REDACTED]","msg":"mail [REDACTED]"}\n<u><Phone>[REDACTED]</Phone></u>\n'
    )
    assert b"Smith" not in proc.stderr
