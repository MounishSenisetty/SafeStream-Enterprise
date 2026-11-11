"""Connector logic against in-memory fakes (no broker needed)."""

from __future__ import annotations

import json
import os
import time
from typing import Any

import pytest
from confluent_kafka import TIMESTAMP_CREATE_TIME, KafkaError, KafkaException
from pydantic import ValidationError

from safestream_enterprise import StructuredRedactor
from safestream_enterprise.connectors.kafka import (
    MAX_TRANSACTION_ATTEMPTS,
    ConnectorConfig,
    DeliveryError,
    KafkaRedactionConnector,
    main,
    watchdog,
)


class FakeMsg:
    def __init__(
        self,
        value: bytes | None,
        key: bytes | None = None,
        err: Any = None,
        headers: list[tuple[str, bytes]] | None = None,
        partition: int = 0,
        offset: int = 7,
    ) -> None:
        self._v, self._k, self._e, self._h = value, key, err, headers
        self._p, self._o = partition, offset

    def value(self) -> bytes | None:
        return self._v

    def key(self) -> bytes | None:
        return self._k

    def error(self) -> Any:
        return self._e

    def headers(self) -> list[tuple[str, bytes]] | None:
        return self._h

    def timestamp(self) -> tuple[int, int]:
        return (TIMESTAMP_CREATE_TIME, 1700000000000)

    def topic(self) -> str:
        return "ingress-logs"

    def partition(self) -> int:
        return self._p

    def offset(self) -> int:
        return self._o


class FakeProducer:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[dict[str, Any]] = []
        self.fail = fail
        self._pending: list[Any] = []

    def produce(self, topic: str, **kw: Any) -> None:
        self.sent.append({"topic": topic, **kw})
        self._pending.append(kw["on_delivery"])

    def poll(self, _t: float) -> int:
        return 0

    def flush(self, _t: float) -> int:
        err = KafkaError(KafkaError._MSG_TIMED_OUT) if self.fail else None
        for cb in self._pending:
            cb(err, None)
        self._pending.clear()
        return 0


class FakeConsumer:
    def __init__(self) -> None:
        self.commits = 0

    def commit(self, asynchronous: bool) -> None:
        assert asynchronous is False
        self.commits += 1


def make(
    producer: FakeProducer, redactor: Any = None
) -> tuple[KafkaRedactionConnector, FakeConsumer]:
    consumer = FakeConsumer()
    conn = KafkaRedactionConnector(
        ConnectorConfig(bootstrap_servers="x"),
        redactor or StructuredRedactor(),
        consumer,
        producer,  # type: ignore[arg-type]
    )
    return conn, consumer


def test_redacts_value_key_headers_and_commits_after_ack() -> None:
    p = FakeProducer()
    conn, c = make(p)
    conn.process_batch(
        [  # type: ignore[list-item]
            FakeMsg(
                b'{"email": "a@b.example", "lvl": "info"}',
                key=b"bob@corp.example",
                headers=[("fwd", b"token for bob@corp.example")],
            ),
            FakeMsg(None, key=b"k1"),  # tombstone
        ]
    )
    first, tomb = p.sent
    assert first["topic"] == "egress-logs-clean"
    assert json.loads(first["value"]) == {"email": "[REDACTED]", "lvl": "info"}
    assert first["key"] == b"[REDACTED]"
    assert first["headers"] == [
        ("fwd", b"token for [REDACTED]"),
        ("x-safestream-redaction", b"structural"),
    ]
    assert first["timestamp"] == 1700000000000
    assert tomb["value"] is None and tomb["key"] == b"k1"
    assert c.commits == 1
    # /metrics view: counts only
    m = conn.snapshot()
    assert (m.egress_records, m.dlq_records, m.batches, m.transaction_aborts) == (2, 0, 1, 0)
    # value + key + header: key and header redactions count too (compliance evidence)
    assert m.redactions == {"email": 3}


def test_delivery_failure_never_commits() -> None:
    conn, c = make(FakeProducer(fail=True))
    with pytest.raises(DeliveryError):
        conn.process_batch([FakeMsg(b"{}")])  # type: ignore[list-item]
    assert c.commits == 0


def test_redaction_crash_goes_to_dlq_not_egress() -> None:
    class Boom:
        def redact_line(self, *_a: Any, **_kw: Any) -> Any:
            raise RuntimeError("secret-bearing message")

    p = FakeProducer()
    conn, c = make(p, Boom())
    conn.process_batch([FakeMsg(b"raw pii")])  # type: ignore[list-item]
    (sent,) = p.sent
    assert sent["topic"] == "ingress-logs-dlq" and sent["value"] == b"raw pii"
    assert sent["headers"] == [("x-safestream-error", b"RuntimeError")]
    assert c.commits == 1


def test_xml_payload_is_redacted_structurally() -> None:
    p = FakeProducer()
    conn, c = make(p)
    conn.process_batch([FakeMsg(b"<log><email>a@b.example</email><lvl>info</lvl></log>")])  # type: ignore[list-item]
    (sent,) = p.sent
    assert sent["topic"] == "egress-logs-clean"
    assert sent["value"] == b"<log><email>[REDACTED]</email><lvl>info</lvl></log>"
    assert sent["headers"] == [("x-safestream-redaction", b"structural")]
    assert c.commits == 1


def test_unparseable_payload_goes_to_dlq_and_loop_continues() -> None:
    p = FakeProducer()
    conn, c = make(p)
    conn.process_batch([FakeMsg(b"plain text bob@corp.example"), FakeMsg(b'{"ok": 1}')])  # type: ignore[list-item]
    dlq, egress = p.sent
    assert dlq["topic"] == "ingress-logs-dlq"
    assert dlq["headers"] == [("x-safestream-error", b"StructuredParseError")]
    assert egress["topic"] == "egress-logs-clean"
    assert c.commits == 1


def test_unparseable_can_be_text_redacted_instead() -> None:
    p = FakeProducer()
    consumer = FakeConsumer()
    conn = KafkaRedactionConnector(
        ConnectorConfig(bootstrap_servers="x", unparseable="redact_text"),
        StructuredRedactor(),
        consumer,
        p,  # type: ignore[arg-type]
    )
    conn.process_batch([FakeMsg(b"plain text bob@corp.example")])  # type: ignore[list-item]
    (sent,) = p.sent
    assert sent["topic"] == "egress-logs-clean" and sent["value"] == b"plain text [REDACTED]"
    assert sent["headers"] == [("x-safestream-redaction", b"text")]


def test_egress_produce_rejection_goes_to_dlq() -> None:
    class Rejecting(FakeProducer):
        def produce(self, topic: str, **kw: Any) -> None:
            if topic == "egress-logs-clean":
                raise KafkaException(KafkaError(KafkaError.MSG_SIZE_TOO_LARGE))
            super().produce(topic, **kw)

    p = Rejecting()
    conn, c = make(p)
    conn.process_batch([FakeMsg(b'{"a": 1}')])  # type: ignore[list-item]
    assert [m["topic"] for m in p.sent] == ["ingress-logs-dlq"]
    assert c.commits == 1


def test_consumer_errors() -> None:
    conn, c = make(FakeProducer())
    conn.process_batch([FakeMsg(None, err=KafkaError(KafkaError._TRANSPORT))])  # type: ignore[list-item]
    assert c.commits == 0  # nothing consumed: no commit (would raise _NO_OFFSET)
    with pytest.raises(KafkaException):
        conn.process_batch([FakeMsg(None, err=KafkaError(KafkaError._FATAL, fatal=True))])  # type: ignore[list-item]


def test_config_from_env() -> None:
    cfg = ConnectorConfig.from_env(
        {
            "KAFKA_BOOTSTRAP_SERVERS": "b:9092",
            "SAFESTREAM_KAFKA_SECURITY_PROTOCOL": "SASL_SSL",
            "SAFESTREAM_KAFKA_SASL_MECHANISM": "SCRAM-SHA-512",
        }
    )
    assert cfg.consumer_config()["security.protocol"] == "SASL_SSL"
    assert cfg.producer_config()["sasl.mechanism"] == "SCRAM-SHA-512"
    assert cfg.consumer_config()["enable.auto.commit"] is False
    assert "SCRAM" not in repr(cfg)  # secrets stay wrapped
    with pytest.raises(ValueError):
        ConnectorConfig.from_env({})


@pytest.mark.parametrize(
    "env",
    [
        {"DLQ_TOPIC": "egress-logs-clean"},  # raw records into the clean topic
        {"EGRESS_TOPIC": "ingress-logs"},  # infinite loop
        {"SAFESTREAM_MODE": "pseudonymize"},  # no HMAC key
        {"SAFESTREAM_BATCH_SIZE": "0"},
        {"SAFESTREAM_UNPARSEABLE": "drop"},
        # liveness shorter than two flush waits would restart healthy pods
        {"SAFESTREAM_LIVENESS_TIMEOUT_S": "30"},
        {"SAFESTREAM_METRICS_PORT": "70000"},
    ],
)
def test_config_rejects_unsafe_values(env: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        ConnectorConfig.from_env({"KAFKA_BOOTSTRAP_SERVERS": "b:9092", **env})


def test_main_never_logs_secret_config_values(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(
        os,
        "environ",
        {
            "KAFKA_BOOTSTRAP_SERVERS": "b:9092",
            "SAFESTREAM_BATCH_SIZE": "s3cr3t-value",
        },
    )
    assert main() == 2
    assert "batch_size" in caplog.text and "s3cr3t-value" not in caplog.text


# --- exactly_once ----------------------------------------------------------


class TxnProducer(FakeProducer):
    """Transactional fake: records only what a read_committed reader would see."""

    def __init__(self, commit_errors: list[KafkaError] | None = None) -> None:
        super().__init__()
        self.commit_errors = list(commit_errors or [])
        self.calls: list[str] = []
        self.visible: list[dict[str, Any]] = []  # records in committed transactions
        self.committed_offsets: list[list[tuple[str, int, int]]] = []
        self._txn: list[dict[str, Any]] = []
        self._txn_offsets: list[tuple[str, int, int]] = []

    def begin_transaction(self) -> None:
        self.calls.append("begin")
        self._txn, self._txn_offsets = [], []

    def produce(self, topic: str, **kw: Any) -> None:
        super().produce(topic, **kw)
        self._txn.append(self.sent[-1])

    def send_offsets_to_transaction(self, offsets: Any, metadata: Any, timeout: float) -> None:
        assert metadata == "group-metadata"
        self.calls.append("send_offsets")
        self._txn_offsets = [(tp.topic, tp.partition, tp.offset) for tp in offsets]

    def commit_transaction(self, timeout: float) -> None:
        self.calls.append("commit")
        if self.commit_errors:
            raise KafkaException(self.commit_errors.pop(0))
        self.visible += self._txn
        self.committed_offsets.append(self._txn_offsets)

    def abort_transaction(self, timeout: float) -> None:
        self.calls.append("abort")
        self._txn = []


class TxnConsumer(FakeConsumer):
    def consumer_group_metadata(self) -> str:
        return "group-metadata"

    def commit(self, asynchronous: bool) -> None:
        raise AssertionError("exactly_once must commit offsets inside the transaction")


def make_eos(producer: TxnProducer) -> KafkaRedactionConnector:
    return KafkaRedactionConnector(
        ConnectorConfig(bootstrap_servers="x", delivery="exactly_once"),
        StructuredRedactor(),
        TxnConsumer(),  # type: ignore[arg-type]
        producer,  # type: ignore[arg-type]
    )


BATCH = [
    FakeMsg(b'{"email": "a@b.example"}', partition=0, offset=10),
    FakeMsg(b"not structured", partition=0, offset=11),  # -> DLQ, same transaction
    FakeMsg(b'{"ok": 1}', partition=1, offset=4),
]


def test_eos_commits_records_dlq_and_offsets_atomically() -> None:
    p = TxnProducer()
    conn = make_eos(p)
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    assert p.calls == ["begin", "send_offsets", "commit"]
    assert [m["topic"] for m in p.visible] == [
        "egress-logs-clean",
        "ingress-logs-dlq",
        "egress-logs-clean",
    ]
    # last offset + 1 per partition, committed inside the transaction
    assert sorted(p.committed_offsets[0]) == [("ingress-logs", 0, 12), ("ingress-logs", 1, 5)]
    assert conn.stats.counts["email"] == 1 and conn.dead_lettered == 1


def test_eos_abortable_error_retries_batch_without_duplicates_or_double_counting() -> None:
    abortable = KafkaError(KafkaError._TIMED_OUT, "boom", txn_requires_abort=True)
    p = TxnProducer(commit_errors=[abortable])
    conn = make_eos(p)
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    attempt = ["begin", "send_offsets", "commit"]
    assert p.calls == [*attempt, "abort", *attempt]
    assert len(p.visible) == 3  # the aborted attempt is invisible
    assert conn.stats.counts["email"] == 1 and conn.dead_lettered == 1
    m = conn.snapshot()  # the retried batch is counted once; the abort is counted
    assert (m.egress_records, m.dlq_records, m.batches, m.transaction_aborts) == (2, 1, 1, 1)


def test_eos_retriable_commit_is_retried_in_place() -> None:
    retriable = KafkaError(KafkaError._TIMED_OUT, "slow", retriable=True)
    p = TxnProducer(commit_errors=[retriable])
    make_eos(p).process_batch(BATCH)  # type: ignore[arg-type]
    assert p.calls == ["begin", "send_offsets", "commit", "commit"]
    assert len(p.visible) == 3


def test_eos_gives_up_after_repeated_aborts() -> None:
    abortable = KafkaError(KafkaError._TIMED_OUT, "boom", txn_requires_abort=True)
    p = TxnProducer(commit_errors=[abortable] * MAX_TRANSACTION_ATTEMPTS)
    with pytest.raises(DeliveryError):
        make_eos(p).process_batch(BATCH)  # type: ignore[arg-type]
    assert p.visible == [] and p.committed_offsets == []


def test_eos_fatal_error_is_raised_not_retried() -> None:
    fenced = KafkaError(KafkaError._FENCED, "fenced", fatal=True)
    p = TxnProducer(commit_errors=[fenced])
    with pytest.raises(KafkaException):
        make_eos(p).process_batch(BATCH)  # type: ignore[arg-type]
    assert p.calls == ["begin", "send_offsets", "commit"]


def test_eos_config() -> None:
    cfg = ConnectorConfig.from_env(
        {"KAFKA_BOOTSTRAP_SERVERS": "b:9092", "SAFESTREAM_DELIVERY": "exactly_once"}
    )
    assert cfg.producer_config()["transactional.id"].startswith("safestream-redactor-")  # type: ignore[union-attr]
    assert "transactional.id" not in ConnectorConfig(bootstrap_servers="b").producer_config()
    pinned = ConnectorConfig(
        bootstrap_servers="b", delivery="exactly_once", transactional_id="redactor-0"
    )
    assert pinned.producer_config()["transactional.id"] == "redactor-0"
    with pytest.raises(ValidationError):  # an id without the mode is a misconfiguration
        ConnectorConfig(bootstrap_servers="b", transactional_id="redactor-0")


# --- pre-release review regressions ------------------------------------------


@pytest.mark.parametrize(
    "key",
    [b"1e3", b"1.50", b" 42", b'{"id": 7}', b"123456789012345678901234", b"user-42", "str-key"],
)
def test_keys_and_headers_without_findings_pass_through_byte_for_byte(key: bytes | str) -> None:
    # re-serialising them would move records to other partitions / corrupt IDs
    p = FakeProducer()
    conn, _ = make(p)
    conn.process_batch([FakeMsg(b'{"a":1}', key=key, headers=[("trace", key)])])  # type: ignore[arg-type, list-item]
    (sent,) = p.sent
    assert sent["key"] == key
    assert sent["headers"][0] == ("trace", key)


def test_protected_kafka_properties_cannot_be_overridden() -> None:
    for name in ("ENABLE_AUTO_COMMIT", "ACKS", "ISOLATION_LEVEL", "ENABLE_IDEMPOTENCE"):
        with pytest.raises(ValidationError, match="may not set"):
            ConnectorConfig.from_env(
                {"KAFKA_BOOTSTRAP_SERVERS": "b:9092", f"SAFESTREAM_KAFKA_{name}": "x"}
            )
    # ordinary client settings (auth, TLS) are still allowed
    ConnectorConfig.from_env(
        {"KAFKA_BOOTSTRAP_SERVERS": "b:9092", "SAFESTREAM_KAFKA_SSL_CA_LOCATION": "/ca.pem"}
    )


def test_commit_retries_keep_the_heartbeat_fresh(monkeypatch: pytest.MonkeyPatch) -> None:
    from safestream_enterprise.connectors import kafka

    clock = iter(range(1000, 2000))
    monkeypatch.setattr(kafka.time, "monotonic", lambda: next(clock))
    retriable = KafkaError(KafkaError._TIMED_OUT, "slow", retriable=True)
    p = TxnProducer(commit_errors=[retriable, retriable, retriable])
    beats: list[float] = []
    original = p.commit_transaction

    def commit(timeout: float) -> None:
        beats.append(conn.heartbeat)
        original(timeout)

    p.commit_transaction = commit  # type: ignore[method-assign]
    conn = make_eos(p)
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    assert len(beats) == 4 and beats == sorted(set(beats))  # refreshed before every attempt


def test_audit_never_reports_an_uncommitted_batch() -> None:
    p = FakeProducer(fail=True)
    conn = KafkaRedactionConnector(
        ConnectorConfig(bootstrap_servers="x", audit_topic="audit"),
        StructuredRedactor(),
        FakeConsumer(),  # type: ignore[arg-type]
        p,  # type: ignore[arg-type]
    )
    with pytest.raises(DeliveryError):
        conn.process_batch([FakeMsg(b'{"email": "a@b.example"}')])  # type: ignore[list-item]
    p.fail = False
    conn._maybe_audit(final=True)  # what run()'s finally does on the way out
    (audit,) = [json.loads(m["value"]) for m in p.sent if m["topic"] == "audit"]
    # the batch will be replayed after restart and counted then, exactly once
    assert audit["records"] == {"egress": 0, "dlq": 0} and audit["redactions"] == {}
    assert conn.snapshot().egress_records == 1  # live metrics still show the attempt


class RejectingProducer(FakeProducer):
    """A broker that refuses every egress record with ``code``; the DLQ accepts."""

    def __init__(self, code: int) -> None:
        super().__init__()
        self.code = code

    def produce(self, topic: str, **kw: Any) -> None:
        self.sent.append({"topic": topic, **kw})
        err = KafkaError(self.code) if topic == "egress-logs-clean" else None
        self._pending.append(lambda _e, m, cb=kw["on_delivery"]: cb(err, m))


def test_record_rejected_for_good_by_the_broker_is_dead_lettered() -> None:
    p = RejectingProducer(KafkaError.MSG_SIZE_TOO_LARGE)
    conn, c = make(p)
    conn.process_batch([FakeMsg(b'{"email": "a@b.example"}', key=b"k")])  # type: ignore[list-item]
    dlq = [m for m in p.sent if m["topic"] == "ingress-logs-dlq"]
    # The original record, tagged with the broker's verdict; offsets move on.
    assert [m["value"] for m in dlq] == [b'{"email": "a@b.example"}']
    assert ("x-safestream-error", b"MSG_SIZE_TOO_LARGE") in dlq[0]["headers"]
    assert (c.commits, conn.egress_records, conn.dead_lettered) == (1, 0, 1)


def test_transient_broker_failure_is_never_dead_lettered() -> None:
    p = RejectingProducer(KafkaError.NOT_ENOUGH_REPLICAS)
    conn, c = make(p)
    with pytest.raises(DeliveryError):
        conn.process_batch([FakeMsg(b'{"a": 1}')])  # type: ignore[list-item]
    assert c.commits == 0 and all(m["topic"] == "egress-logs-clean" for m in p.sent)


def test_watchdog_exits_only_when_the_main_loop_has_stalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn, _ = make(FakeProducer())
    checks = iter(range(3))

    def fresh_then_stale(_s: float) -> None:
        # Two healthy checks, then the loop stops advancing.
        conn.heartbeat = time.monotonic() - (0 if next(checks) < 2 else 999)

    monkeypatch.setattr(time, "sleep", fresh_then_stale)
    codes: list[int] = []
    watchdog(conn, timeout_s=120, exit_process=codes.append)
    assert codes == [3]
