"""safestream-dlq against in-memory fakes; test_kafka_integration has the real-broker test."""

from __future__ import annotations

from typing import Any

import pytest
from confluent_kafka import TIMESTAMP_CREATE_TIME, KafkaError

from safestream_enterprise import dlq
from safestream_enterprise.connectors.kafka import ConnectorConfig

CONFIG = ConnectorConfig(bootstrap_servers="x")


class Msg:
    def __init__(self, offset: int, reason: str | None = None, eof: bool = False) -> None:
        self._offset, self._reason, self._eof = offset, reason, eof

    def error(self) -> Any:
        return KafkaError(KafkaError._PARTITION_EOF) if self._eof else None

    def partition(self) -> int:
        return 0

    def offset(self) -> int:
        return self._offset

    def value(self) -> bytes:
        return b"record-%d" % self._offset

    def key(self) -> bytes:
        return b"k"

    def headers(self) -> list[tuple[str, bytes]]:
        tag = [("x-safestream-error", self._reason.encode())] if self._reason else []
        return [("fwd", b"h"), *tag]

    def timestamp(self) -> tuple[int, int]:
        return (TIMESTAMP_CREATE_TIME, 1700000000000)


class FakeConsumer:
    def __init__(self, messages: list[Msg]) -> None:
        self.messages = [*messages, Msg(len(messages), eof=True)]
        self.assigned: list[Any] = []
        self.committed: list[Any] | None = None

    def list_topics(self, topic: str, timeout: float) -> Any:
        meta = type("T", (), {"error": None, "partitions": {0: None}})()
        return type("M", (), {"topics": {topic: meta}})()

    def assign(self, partitions: list[Any]) -> None:
        self.assigned = partitions

    def poll(self, _t: float) -> Msg | None:
        return self.messages.pop(0) if self.messages else None

    def commit(self, offsets: list[Any], asynchronous: bool) -> None:
        assert asynchronous is False
        self.committed = offsets


class FakeProducer:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[dict[str, Any]] = []
        self.fail = fail

    def produce(self, topic: str, **kw: Any) -> None:
        self.sent.append({"topic": topic, **kw})

    def poll(self, _t: float) -> int:
        return 0

    def flush(self, _t: float) -> int:
        for m in self.sent:
            m["on_delivery"](KafkaError(KafkaError._MSG_TIMED_OUT) if self.fail else None, None)
        return 0


DLQ = [Msg(0, "StructuredParseError"), Msg(1, "MSG_SIZE_TOO_LARGE"), Msg(2, "StructuredParseError")]


def test_summary_counts_by_error_and_commits_nothing() -> None:
    c = FakeConsumer(list(DLQ))
    out = dlq.run(CONFIG, c, None)  # type: ignore[arg-type]
    assert out["records"] == 3
    assert out["by_error"] == {"MSG_SIZE_TOO_LARGE": 1, "StructuredParseError": 2}
    assert c.committed is None and "replayed" not in out


def test_replay_goes_to_ingress_without_the_error_tag_then_commits() -> None:
    c, p = FakeConsumer(list(DLQ)), FakeProducer()
    out = dlq.run(CONFIG, c, p, error="StructuredParseError")  # type: ignore[arg-type]
    assert (out["replayed"], out["skipped"]) == (2, 1)
    # Unredacted originals: to ingress (through redaction again), never to the clean topic.
    assert {m["topic"] for m in p.sent} == {"ingress-logs"}
    assert [m["value"] for m in p.sent] == [b"record-0", b"record-2"]
    assert all(m["headers"] == [("fwd", b"h")] for m in p.sent)
    assert c.committed is not None and c.committed[0].offset == 3


def test_limit_stops_early_and_commits_only_what_was_read() -> None:
    c, p = FakeConsumer(list(DLQ)), FakeProducer()
    out = dlq.run(CONFIG, c, p, limit=1)  # type: ignore[arg-type]
    assert out["replayed"] == 1
    assert c.committed is not None and c.committed[0].offset == 1


def test_unacknowledged_replay_commits_nothing() -> None:
    c, p = FakeConsumer(list(DLQ)), FakeProducer(fail=True)
    with pytest.raises(dlq.ReplayError):
        dlq.run(CONFIG, c, p)  # type: ignore[arg-type]
    assert c.committed is None


def test_main_rejects_bad_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KAFKA_BOOTSTRAP_SERVERS", raising=False)
    assert dlq.main(["summary"]) == 2
