"""Leak canaries: synthetic PII through the live redactor, counts out."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from safestream_redactor import RedactionMode

from safestream_enterprise.canary import Canary, Seed
from safestream_enterprise.connectors.health import render_metrics
from safestream_enterprise.connectors.kafka import ConnectorConfig, KafkaRedactionConnector
from safestream_enterprise.rules import make_redactor
from test_kafka import FakeConsumer, FakeProducer


class Passthrough:
    """A redactor that redacts nothing: what a canary exists to catch."""

    def redact_line(self, data: bytes, _stats: Any, strict: bool = True) -> Any:
        class Out:
            pass

        out = Out()
        out.data = data  # type: ignore[attr-defined]
        return out


class Raises:
    def redact_line(self, *_a: Any, **_k: Any) -> Any:
        raise RuntimeError("cannot parse")


def luhn_ok(number: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(number)):
        d = int(ch) * (2 if i % 2 else 1)
        total += d - 9 if d > 9 else d
    return total % 10 == 0


def test_seeds_are_fresh_fake_and_well_formed() -> None:
    seeds = [Seed.new() for _ in range(50)]
    assert len({s.tag for s in seeds}) == 50
    for s in seeds:
        assert s.email.endswith("@example.com")
        assert len(s.card) == 16 and s.card.startswith("4") and luhn_ok(s.card)
        assert re.fullmatch(r"[1-5]\d\d-\d\d-\d{4}", s.ssn)
        records = s.records()
        assert json.loads(records["json"])["email"] == s.email
        assert records["xml"].startswith(b"<event>")


@pytest.mark.parametrize("mode", ["replace", "mask", "pseudonymize"])
def test_the_built_in_rules_never_leak_a_canary(mode: str) -> None:
    redactor = make_redactor(RedactionMode(mode), b"k" * 32)
    canary = Canary()
    results = [canary.check(redactor) for _ in range(50)]
    assert all(r.checks == 2 and r.leaked == () for r in results)


def test_a_redactor_that_lets_pii_through_is_caught_in_both_formats() -> None:
    assert Canary().check(Passthrough()).leaked == ("json", "xml")  # type: ignore[arg-type]


def test_a_redactor_that_fails_closed_is_not_a_leak() -> None:
    assert Canary().check(Raises()).leaked == ()  # type: ignore[arg-type]


def connector(redactor: Any = None, **kw: Any) -> KafkaRedactionConnector:
    cfg = ConnectorConfig(bootstrap_servers="x", **kw)
    return KafkaRedactionConnector(
        cfg,
        redactor or make_redactor(RedactionMode.REPLACE),
        FakeConsumer(),  # type: ignore[arg-type]
        FakeProducer(),  # type: ignore[arg-type]
    )


def run_canary(conn: KafkaRedactionConnector) -> None:
    conn._canary_due = 0.0
    conn._maybe_canary()


def test_leaks_are_counted_and_exposed_without_values(caplog: pytest.LogCaptureFixture) -> None:
    conn = connector(Passthrough())
    run_canary(conn)
    run_canary(conn)
    assert (conn.canary_checks, conn.canary_leaks) == (4, 4)
    assert conn._running  # report mode: redaction carries on
    text = render_metrics(conn.snapshot(), 0.0)
    assert "safestream_canary_leaks_total 4" in text
    assert "safestream_canary_checks_total 4" in text
    assert "LEAK CANARY" in caplog.text
    assert "example.com" not in caplog.text and "canary." not in caplog.text


def test_stop_mode_stops_the_connector_on_a_leak() -> None:
    conn = connector(Passthrough(), canary_on_leak="stop")
    run_canary(conn)
    assert not conn._running and conn.canary_stopped


def test_canaries_run_on_their_interval_only() -> None:
    conn = connector(canary_interval_s=3600)
    conn._maybe_canary()  # due on the first loop iteration
    conn._maybe_canary()
    assert conn.canary_checks == 2


def test_canaries_can_be_turned_off() -> None:
    conn = connector(Passthrough(), canary_interval_s=0, audit_topic="safestream-audit")
    run_canary(conn)
    assert conn.canary_checks == 0 and conn.snapshot().canary is None
    assert "safestream_canary" not in render_metrics(conn.snapshot(), 0.0)
    conn._audit_due = 0.0
    conn._maybe_audit()
    producer = conn.producer
    assert isinstance(producer, FakeProducer)
    assert json.loads(producer.sent[-1]["value"])["canary"] is None


def test_each_audit_window_reports_its_own_canaries() -> None:
    conn = connector(Passthrough(), audit_topic="safestream-audit")
    producer = conn.producer
    assert isinstance(producer, FakeProducer)
    for runs in (2, 0, 1):
        for _ in range(runs):
            run_canary(conn)
        conn._audit_due = 0.0
        conn._maybe_audit()
    windows = [json.loads(m["value"])["canary"] for m in producer.sent]
    assert windows == [
        {"checks": 4, "leaks": 4},
        {"checks": 0, "leaks": 0},
        {"checks": 2, "leaks": 2},
    ]
