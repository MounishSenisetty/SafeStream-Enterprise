"""Connector logic against in-memory fakes (no broker needed)."""

from __future__ import annotations

import json
import os
from typing import Any

import pytest
from confluent_kafka import TIMESTAMP_CREATE_TIME, KafkaError, KafkaException
from pydantic import ValidationError

from safestream_enterprise import StructuredRedactor
from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    DeliveryError,
    KafkaRedactionConnector,
    main,
)


class FakeMsg:
    def __init__(
        self,
        value: bytes | None,
        key: bytes | None = None,
        err: Any = None,
        headers: list[tuple[str, bytes]] | None = None,
    ) -> None:
        self._v, self._k, self._e, self._h = value, key, err, headers

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
        return 0

    def offset(self) -> int:
        return 7


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
