"""Broker-level tests: the connector against a real Kafka.

Skipped unless ``SAFESTREAM_IT_BOOTSTRAP`` names a broker (CI starts one as a
service container). ``SAFESTREAM_IT_IMAGE`` additionally runs the built Docker
image with the same restrictions the Kubernetes manifest applies.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator

import pytest
from confluent_kafka import Consumer, Message, Producer, TopicPartition
from confluent_kafka.admin import AdminClient, NewTopic

from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    KafkaRedactionConnector,
    build_redactor,
)

BOOTSTRAP = os.environ.get("SAFESTREAM_IT_BOOTSTRAP", "")
IMAGE = os.environ.get("SAFESTREAM_IT_IMAGE", "")
pytestmark = pytest.mark.skipif(not BOOTSTRAP, reason="SAFESTREAM_IT_BOOTSTRAP not set")

PII_RECORD = {"LastName": "Smith", "password": "hunter2", "msg": "mail bob@corp.example"}


@pytest.fixture
def topics() -> Iterator[dict[str, str]]:
    """Fresh single-partition topics per test, so runs never see each other's data."""
    suffix = uuid.uuid4().hex[:8]
    names = {k: f"it-{k}-{suffix}" for k in ("ingress", "egress", "dlq")}
    admin = AdminClient({"bootstrap.servers": BOOTSTRAP})
    new = [NewTopic(t, num_partitions=1, replication_factor=1) for t in names.values()]
    for future in admin.create_topics(new).values():
        future.result(30)
    yield names
    admin.delete_topics(list(names.values()))


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


def test_end_to_end_redaction_dlq_commit_and_resume(topics: dict[str, str]) -> None:
    group = f"it-connector-{uuid.uuid4().hex[:8]}"
    config = ConnectorConfig(
        bootstrap_servers=BOOTSTRAP,
        group_id=group,
        ingress_topic=topics["ingress"],
        egress_topic=topics["egress"],
        dlq_topic=topics["dlq"],
        poll_timeout_s=0.5,
    )
    produce(
        topics["ingress"],
        [
            (b"bob@corp.example", json.dumps(PII_RECORD).encode()),
            (None, b"plain text, not json: alice@corp.example"),
            (b"user-42", None),  # tombstone
        ],
        headers=[("fwd", b"token for bob@corp.example")],
    )

    with Running(config):
        egress = drain(topics["egress"], 2)
        dlq = drain(topics["dlq"], 1)

    # Clean topic: JSON record redacted structurally; key and header redacted too.
    assert len(egress) == 2, [m.value() for m in egress]
    record, tombstone = egress
    assert json.loads(record.value()) == {
        "LastName": "[REDACTED]",
        "password": "[REDACTED]",
        "msg": "mail [REDACTED]",
    }
    assert record.key() == b"[REDACTED]"
    headers = dict(record.headers() or [])
    assert headers == {"fwd": b"token for [REDACTED]", "x-safestream-redaction": b"structural"}
    assert tombstone.value() is None and tombstone.key() == b"user-42"

    # DLQ: the non-JSON record, untouched, tagged with the exception class only.
    assert len(dlq) == 1
    assert dlq[0].value() == b"plain text, not json: alice@corp.example"
    assert dict(dlq[0].headers() or [])["x-safestream-error"] == b"StructuredParseError"

    # Offsets were committed only after egress acknowledged: nothing left to replay.
    assert committed_lag(group, topics["ingress"]) == 0

    # A restarted connector in the same group resumes after the committed offset:
    # the new record is processed and nothing earlier is replayed.
    produce(topics["ingress"], [(None, b'{"email": "carol@corp.example"}')])
    with Running(config):
        egress = drain(topics["egress"], 3)
    assert len(egress) == 3, "earlier records were replayed or the new one was lost"
    assert json.loads(egress[2].value()) == {"email": "[REDACTED]"}
    assert committed_lag(group, topics["ingress"]) == 0


@pytest.mark.skipif(not IMAGE, reason="SAFESTREAM_IT_IMAGE not set")
def test_container_image_under_kubernetes_restrictions(topics: dict[str, str]) -> None:
    """The distroless image, read-only, all capabilities dropped, non-root."""
    name = f"it-{uuid.uuid4().hex[:8]}"
    env = {
        "KAFKA_BOOTSTRAP_SERVERS": BOOTSTRAP,
        "KAFKA_GROUP_ID": name,
        "INGRESS_TOPIC": topics["ingress"],
        "EGRESS_TOPIC": topics["egress"],
        "DLQ_TOPIC": topics["dlq"],
        "SAFESTREAM_MODE": "pseudonymize",
        "SAFESTREAM_HMAC_KEY": "ci-only-key-" + "x" * 32,
    }
    run = ["docker", "run", "-d", "--name", name, "--network", "host", "--read-only"]
    run += ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", "65532:65532"]
    for k, v in env.items():
        run += ["-e", f"{k}={v}"]
    subprocess.run([*run, IMAGE], check=True, capture_output=True)
    try:
        produce(topics["ingress"], [(None, json.dumps(PII_RECORD).encode())])
        egress = drain(topics["egress"], 1, timeout_s=90)
        assert len(egress) == 1
        out = json.loads(egress[0].value())
        assert out["LastName"].startswith("<PERSON_") and out["password"].startswith("<SECRET_")
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
        # Operational logs never carry record content or secrets.
        for leaked in ("Smith", "hunter2", "bob@corp.example", env["SAFESTREAM_HMAC_KEY"]):
            assert leaked not in logs.stdout + logs.stderr
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
