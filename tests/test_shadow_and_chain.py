"""Shadow evaluation of a candidate policy, and the audit hash chain."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safestream_enterprise import audit, policy
from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    KafkaRedactionConnector,
    build_redactor,
    load_policy,
)
from test_kafka import FakeConsumer, FakeMsg, FakeProducer

KEY = Ed25519PrivateKey.generate()
PUBLIC = policy.encode_public_key(KEY.public_key())
LOYALTY = {"*loyalty_number*": "id_number"}
RECORD = b'{"loyalty_number":"L-4242-77","email":"bob@corp.example"}'


def signed(version: int, rules: dict[str, str], key: Ed25519PrivateKey = KEY) -> bytes:
    return policy.sign({"rules": rules}, key, "acme", version)


def make(tmp_path: Path, **config: Any) -> tuple[KafkaRedactionConnector, FakeProducer]:
    """A connector on policy version 1 (built-in rules only), with fakes for Kafka."""
    (tmp_path / "policy.json").write_bytes(signed(1, {}))
    cfg = ConnectorConfig(
        bootstrap_servers="x",
        policy_file=tmp_path / "policy.json",
        policy_public_keys=PUBLIC,
        shadow_policy_file=tmp_path / "candidate.json",
        **config,
    )
    source, verified = load_policy(cfg)
    producer = FakeProducer()
    conn = KafkaRedactionConnector(
        cfg,
        build_redactor(cfg, verified),
        FakeConsumer(),  # type: ignore[arg-type]
        producer,  # type: ignore[arg-type]
        source,
        verified,
    )
    return conn, producer


def reload(conn: KafkaRedactionConnector) -> None:
    conn._policy_due = 0.0
    conn._maybe_reload_policy()


def process(conn: KafkaRedactionConnector, n: int = 1) -> None:
    conn.process_batch([FakeMsg(RECORD, offset=i) for i in range(n)])  # type: ignore[misc]


def egress(producer: FakeProducer) -> list[bytes]:
    return [m["value"] for m in producer.sent if m["topic"] == "egress-logs-clean"]


# ----------------------------------------------------------------------
# shadow mode
# ----------------------------------------------------------------------


def test_candidate_is_compared_but_never_published(tmp_path: Path) -> None:
    conn, producer = make(tmp_path)
    reload(conn)
    assert conn.shadow is None  # no candidate file: nothing to evaluate
    process(conn, 2)

    (tmp_path / "candidate.json").write_bytes(signed(2, LOYALTY))
    reload(conn)
    process(conn, 3)

    # Output is the policy in force, before and after the candidate appeared:
    # the loyalty number is still there.
    assert set(egress(producer)) == {b'{"loyalty_number":"L-4242-77","email":"[REDACTED]"}'}
    report = conn.snapshot().shadow
    assert report is not None
    assert report["candidate"]["version"] == 2
    assert (report["records"], report["changed_records"], report["errors"]) == (3, 3, 0)
    # What promoting it would change, in counts: three more id_number redactions,
    # and nothing the policy in force catches would be lost.
    assert report["redactions"] == {
        "active": {"email": 3},
        "candidate": {"email": 3, "id_number": 3},
    }
    assert "L-4242-77" not in json.dumps(report)


def test_sampling_shadows_every_nth_record(tmp_path: Path) -> None:
    conn, _ = make(tmp_path, shadow_sample_every=5)
    (tmp_path / "candidate.json").write_bytes(signed(2, LOYALTY))
    reload(conn)
    process(conn, 20)
    assert conn.shadow is not None and conn.shadow.records == 4


def test_untrusted_candidate_is_refused_and_redaction_carries_on(tmp_path: Path) -> None:
    conn, producer = make(tmp_path)
    (tmp_path / "candidate.json").write_bytes(signed(2, LOYALTY, key=Ed25519PrivateKey.generate()))
    reload(conn)
    process(conn)
    assert conn.shadow is None and conn.policy_rejections == 1
    assert len(egress(producer)) == 1


def test_shadow_ends_when_the_candidate_is_promoted_or_withdrawn(tmp_path: Path) -> None:
    conn, producer = make(tmp_path)
    candidate = tmp_path / "candidate.json"
    candidate.write_bytes(signed(2, LOYALTY))
    reload(conn)
    assert conn.shadow is not None

    # Promote: the same signed bundle becomes the policy file.
    (tmp_path / "policy.json").write_bytes(candidate.read_bytes())
    reload(conn)
    assert conn.policy is not None and conn.policy.version == 2
    assert conn.shadow is None
    process(conn)
    assert egress(producer)[-1] == b'{"loyalty_number":"[REDACTED]","email":"[REDACTED]"}'

    candidate.write_bytes(signed(3, {}))
    reload(conn)
    assert conn.shadow is not None and conn.shadow.policy.version == 3
    candidate.unlink()  # withdrawn
    reload(conn)
    assert conn.shadow is None


def test_a_failing_candidate_never_affects_the_real_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn, producer = make(tmp_path)
    (tmp_path / "candidate.json").write_bytes(signed(2, LOYALTY))
    reload(conn)
    assert conn.shadow is not None

    def boom(*_a: object, **_k: object) -> None:
        raise RuntimeError("candidate bug")

    monkeypatch.setattr(conn.shadow.redactor, "redact_line", boom)
    process(conn, 2)
    assert len(egress(producer)) == 2 and conn.dead_lettered == 0
    assert (conn.shadow.errors, conn.shadow.records) == (2, 0)


def test_shadow_needs_a_signed_policy() -> None:
    with pytest.raises(ValueError, match="requires SAFESTREAM_POLICY_FILE"):
        ConnectorConfig(bootstrap_servers="x", shadow_policy_file="c.json")  # type: ignore[arg-type]


# ----------------------------------------------------------------------
# audit hash chain
# ----------------------------------------------------------------------


def published_audits(tmp_path: Path, windows: int = 4) -> list[bytes]:
    """Audit events as a connector publishes them, one per window."""
    conn, producer = make(tmp_path, audit_topic="safestream-audit")
    for i in range(windows):
        process(conn, i + 1)
        conn._audit_due = 0.0
        conn._maybe_audit(final=i == windows - 1)
    return [m["value"] for m in producer.sent if m["topic"] == "safestream-audit"]


def test_events_form_a_chain_that_verifies(tmp_path: Path) -> None:
    events = published_audits(tmp_path)
    links = [json.loads(e)["chain"] for e in events]
    assert [link["seq"] for link in links] == [0, 1, 2, 3]
    assert links[0]["prev"] is None and links[1]["prev"] == audit.event_hash(events[0])
    assert json.loads(events[0])["schema"] == "safestream.audit/v2"

    (chain,), unchained = audit.verify(events)
    assert chain.problems == [] and chain.closed and chain.events == 4 and unchained == 0
    assert chain.head == audit.event_hash(events[-1])


@pytest.mark.parametrize(
    ("tamper", "problem"),
    [
        (lambda e: [e[0], e[1].replace(b'"egress":2', b'"egress":9'), *e[2:]], "altered"),
        (lambda e: [e[0], e[2], e[3]], "missing"),
        (lambda e: [e[1], e[0], e[2], e[3]], "missing"),  # reordered
        (lambda e: [*e, e[3]], "out of order"),  # replayed
    ],
)
def test_tampering_is_detected(tmp_path: Path, tamper: Any, problem: str) -> None:
    events = published_audits(tmp_path)
    assert b'"egress":2' in events[1]
    (chain,), _ = audit.verify(tamper(events))
    assert any(problem in p for p in chain.problems), chain.problems


def test_cli_reports_and_checks_recorded_heads(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    events = published_audits(tmp_path)
    export = tmp_path / "audit.ndjson"
    export.write_bytes(b"\n".join(events) + b"\n")
    assert audit.main(["verify", str(export), "--require-closed"]) == 0
    report = json.loads(capsys.readouterr().out)
    chain_id, head = report["chains"][0]["chain"], report["chains"][0]["head"]
    assert report["intact"] and report["chains"][0]["events"] == 4

    # A head recorded after the second event still checks out once more events exist...
    earlier = audit.event_hash(events[1])
    assert audit.main(["verify", str(export), "--head", f"{chain_id}={earlier}"]) == 0
    capsys.readouterr()
    # ...but truncating the tail is only caught by the recorded head,
    truncated = tmp_path / "truncated.ndjson"
    truncated.write_bytes(b"\n".join(events[:2]) + b"\n")
    assert audit.main(["verify", str(truncated)]) == 0
    capsys.readouterr()
    assert audit.main(["verify", str(truncated), "--head", f"{chain_id}={head}"]) == 1
    assert "does not contain the recorded head" in capsys.readouterr().out
    # or by requiring a clean close.
    assert audit.main(["verify", str(truncated), "--require-closed"]) == 1
    capsys.readouterr()
    # A chain that was deleted outright is reported as absent.
    assert audit.main(["verify", str(export), "--head", "gone-chain=sha256:00"]) == 1
    assert "recorded chain is absent" in capsys.readouterr().out


def test_failed_audit_send_keeps_the_same_place_in_the_chain(tmp_path: Path) -> None:
    conn, producer = make(tmp_path, audit_topic="safestream-audit")
    process(conn)
    producer.fail = True
    conn._audit_due = 0.0
    conn._maybe_audit()
    assert (conn.audit_failures, conn._chain_seq) == (1, 0)
    producer.fail = False
    conn._audit_due = 0.0
    conn._maybe_audit()
    acknowledged = [m["value"] for m in producer.sent if m["topic"] == "safestream-audit"][-1]
    assert json.loads(acknowledged)["chain"] == {"id": conn._chain_id, "seq": 0, "prev": None}
