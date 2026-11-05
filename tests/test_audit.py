"""Compliance audit events, against the in-memory Kafka fakes."""

from __future__ import annotations

import json
import socket
from typing import Any

import pytest
from confluent_kafka import KafkaError, KafkaException
from pydantic import ValidationError

from safestream_enterprise import DEFAULT_FIELD_RULES, StructuredRedactor, __version__
from safestream_enterprise.connectors.kafka import (
    AUDIT_SCHEMA,
    ConnectorConfig,
    KafkaRedactionConnector,
)
from test_kafka import FakeConsumer, FakeMsg, FakeProducer, TxnConsumer, TxnProducer

BATCH = [FakeMsg(b'{"email": "a@b.example"}', offset=1), FakeMsg(b"not structured", offset=2)]


def connector(producer: Any, **config: Any) -> KafkaRedactionConnector:
    consumer = TxnConsumer() if config.get("delivery") == "exactly_once" else FakeConsumer()
    return KafkaRedactionConnector(
        ConnectorConfig(bootstrap_servers="x", audit_topic="audit", **config),
        StructuredRedactor(),
        consumer,  # type: ignore[arg-type]
        producer,
    )


def audits(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [json.loads(m["value"]) for m in messages if m["topic"] == "audit"]


def test_event_reports_window_counts_and_configuration() -> None:
    p = FakeProducer()
    conn = connector(p)
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    conn._maybe_audit(final=True)
    (event,) = audits(p.sent)
    assert event["schema"] == AUDIT_SCHEMA and event["connector_version"] == __version__
    assert event["records"] == {"egress": 1, "dlq": 1}
    assert event["redactions"] == {"email": 1}
    assert (event["batches"], event["transaction_aborts"]) == (1, 0)
    assert (event["delivery"], event["redaction_mode"]) == ("at_least_once", "replace")
    assert event["field_rules"]["count"] == len(DEFAULT_FIELD_RULES)
    assert event["field_rules"]["fingerprint"].startswith("sha256:")
    assert event["window"]["final"] is True
    assert event["instance"] == socket.gethostname()
    assert p.sent[-1]["key"] == socket.gethostname().encode()
    assert conn.audit_events == 1
    # content-free: no record values anywhere in the event
    assert "a@b.example" not in json.dumps(event) and "not structured" not in json.dumps(event)

    # the next window starts where this one ended and reports only new activity
    conn._maybe_audit(final=True)
    nxt = audits(p.sent)[-1]
    assert nxt["window"]["start"] == event["window"]["end"]
    assert nxt["records"] == {"egress": 0, "dlq": 0} and nxt["redactions"] == {}


def test_not_due_until_the_interval_elapses() -> None:
    p = FakeProducer()
    conn = connector(p, audit_interval_s=60)
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    conn._maybe_audit()
    assert audits(p.sent) == []
    conn._audit_due = 0.0  # interval elapsed
    conn._maybe_audit()
    assert len(audits(p.sent)) == 1


def test_failed_audit_is_carried_into_the_next_window() -> None:
    p = FakeProducer()
    conn = connector(p)
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    start = conn._audit_window_start
    p.fail = True
    conn._maybe_audit(final=True)  # not acknowledged: logged and counted, not raised
    assert (conn.audit_events, conn.audit_failures) == (0, 1)
    p.fail = False
    conn.process_batch([FakeMsg(b'{"email": "c@d.example"}', offset=3)])  # type: ignore[list-item]
    conn._maybe_audit(final=True)
    event = audits(p.sent)[-1]
    # covers both batches, from the original window start: nothing lost
    assert event["records"] == {"egress": 2, "dlq": 1} and event["redactions"] == {"email": 2}
    assert event["window"]["start"] == start.isoformat(timespec="milliseconds")
    assert (conn.audit_events, conn.audit_failures) == (1, 1)
    assert conn.snapshot().audit_failures == 1  # visible in /metrics


def test_exactly_once_audit_runs_in_its_own_transaction() -> None:
    p = TxnProducer()
    conn = connector(p, delivery="exactly_once")
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    conn._maybe_audit(final=True)
    batch_txn = ["begin", "send_offsets", "commit"]
    assert p.calls == [*batch_txn, "begin", "commit"]
    assert audits(p.visible)[0]["records"] == {"egress": 1, "dlq": 1}


def test_exactly_once_audit_abort_is_not_fatal() -> None:
    p = TxnProducer()
    conn = connector(p, delivery="exactly_once")
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    p.commit_errors = [KafkaError(KafkaError._TIMED_OUT, "x", txn_requires_abort=True)]
    conn._maybe_audit(final=True)
    assert p.calls[-1] == "abort" and audits(p.visible) == []
    assert conn.audit_failures == 1
    conn._maybe_audit(final=True)  # retried next window, with the same counts
    assert audits(p.visible)[0]["records"] == {"egress": 1, "dlq": 1}


def test_fatal_error_on_audit_propagates() -> None:
    p = TxnProducer()
    conn = connector(p, delivery="exactly_once")
    p.commit_errors = [KafkaError(KafkaError._FENCED, "fenced", fatal=True)]
    with pytest.raises(KafkaException):
        conn._maybe_audit(final=True)


def test_disabled_by_default() -> None:
    p = FakeProducer()
    conn = KafkaRedactionConnector(
        ConnectorConfig(bootstrap_servers="x"),
        StructuredRedactor(),
        FakeConsumer(),  # type: ignore[arg-type]
        p,  # type: ignore[arg-type]
    )
    conn.process_batch(BATCH)  # type: ignore[arg-type]
    conn._maybe_audit(final=True)
    assert all(m["topic"] != "audit" for m in p.sent)


@pytest.mark.parametrize(
    "bad",
    [
        {"audit_topic": "egress-logs-clean"},  # would mix audit events into clean data
        {"audit_topic": "ingress-logs"},
        {"audit_topic": "audit", "audit_interval_s": 0.5},
    ],
)
def test_config_rejects_unsafe_audit_settings(bad: dict[str, Any]) -> None:
    with pytest.raises(ValidationError):
        ConnectorConfig(bootstrap_servers="x", **bad)


def test_rules_fingerprint_identifies_the_exact_rule_table() -> None:
    a = StructuredRedactor(field_rules={"*a*": "secret", "*b*": "email"})
    assert (
        a.rules_fingerprint
        == StructuredRedactor(field_rules={"*a*": "secret", "*b*": "email"}).rules_fingerprint
    )
    # order matters (first match wins), and so do types
    assert (
        a.rules_fingerprint
        != StructuredRedactor(field_rules={"*b*": "email", "*a*": "secret"}).rules_fingerprint
    )
    assert (
        a.rules_fingerprint
        != StructuredRedactor(field_rules={"*a*": "secret", "*b*": "phone"}).rules_fingerprint
    )
    assert a.rule_count == 2
