"""The uplink contract, held from both sides.

control-plane/test/fixtures/audit-event.json is an audit event as this
connector builds it, with every optional part filled in (signed policy,
shadow evaluation, leak canaries). This test fails if the connector's event
changes shape without the fixture; control-plane/test/api.test.ts posts the
same file to the Worker and fails if the Worker would refuse it. So neither
side can change the format alone.

Regenerate after a deliberate change with
``SAFESTREAM_REGENERATE_FIXTURES=1 pytest tests/test_control_contract.py``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safestream_enterprise import control, policy
from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    KafkaRedactionConnector,
    build_redactor,
    load_policy,
)
from test_kafka import FakeConsumer, FakeMsg, FakeProducer

FIXTURE = Path(__file__).resolve().parent.parent / "control-plane/test/fixtures/audit-event.json"
#: The tenant the Worker test creates to post the fixture as.
TENANT = "contract-acme"


def shape(value: Any) -> Any:
    """Keys and value types, recursively: what must not drift."""
    if isinstance(value, dict):
        return {k: shape(v) for k, v in value.items()}
    return type(value).__name__


def build_event(tmp_path: Path) -> dict[str, Any]:
    key = Ed25519PrivateKey.generate()
    (tmp_path / "policy.json").write_bytes(policy.sign({"rules": {}}, key, TENANT, 1))
    (tmp_path / "candidate.json").write_bytes(
        policy.sign({"rules": {"*loyalty_number*": "id_number"}}, key, TENANT, 2)
    )
    cfg = ConnectorConfig(
        bootstrap_servers="x",
        policy_file=tmp_path / "policy.json",
        policy_public_keys=policy.encode_public_key(key.public_key()),
        shadow_policy_file=tmp_path / "candidate.json",
        audit_topic="safestream-audit",
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
    conn.instance = "safestream-kafka-redactor-7d9f8-x2k4q"
    conn._chain_id = f"{conn.instance}-20261111T090000000000Z"
    conn._maybe_reload_policy()  # starts shadow evaluation of the candidate
    record = b'{"loyalty_number":"L-1","email":"bob@corp.example"}'
    conn.process_batch([FakeMsg(record, offset=i) for i in range(3)])  # type: ignore[misc]
    conn._canary_due = 0.0
    conn._maybe_canary()
    conn._audit_due = 0.0
    conn._maybe_audit()
    events = [json.loads(m["value"]) for m in producer.sent if m["topic"] == "safestream-audit"]
    event: dict[str, Any] = events[-1]
    return event


def test_the_connector_still_builds_the_event_the_worker_was_tested_with(tmp_path: Path) -> None:
    event = build_event(tmp_path)
    assert event["shadow"] is not None and event["canary"] is not None
    if os.environ.get("SAFESTREAM_REGENERATE_FIXTURES"):
        # Stable values, so the fixture diff shows only real changes.
        event["policy"]["key_id"] = event["shadow"]["candidate"]["key_id"] = "9a41c0de52b7f310"
        event["field_rules"]["fingerprint"] = "sha256:" + "ab" * 32
        event["shadow"]["since"] = "2026-11-11T09:00:00+00:00"
        event["window"] = {
            "start": "2026-11-11T09:00:00.000+00:00",
            "end": "2026-11-11T09:01:00.000+00:00",
            "final": False,
        }
        FIXTURE.write_text(json.dumps(event, indent=2) + "\n")
    fixture = json.loads(FIXTURE.read_text())
    assert shape(event) == shape(fixture)


def test_the_fixture_is_content_free() -> None:
    control.check_content_free(json.loads(FIXTURE.read_text()))
