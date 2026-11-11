"""Signed policy bundles: what is accepted, and every way one is refused."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safestream_enterprise import StructuredRedactor, policy
from safestream_enterprise.connectors.kafka import ConnectorConfig, KafkaRedactionConnector
from safestream_enterprise.policy import Policy, PolicyError, PolicySource

KEY = Ed25519PrivateKey.generate()
OTHER_KEY = Ed25519PrivateKey.generate()
TRUSTED = {policy.key_id(KEY.public_key()): KEY.public_key()}
RULES: dict[str, Any] = {"mode": "extend", "rules": {"*loyalty_number*": "id_number"}}


def bundle(version: int = 1, key: Ed25519PrivateKey = KEY, **kw: Any) -> bytes:
    return policy.sign(kw.pop("rules", RULES), key, kw.pop("tenant", "acme"), version)


def edited(data: bytes, **payload_changes: Any) -> bytes:
    """``data`` with its payload changed and the original signature kept."""
    doc = json.loads(data)
    payload = {**json.loads(base64.b64decode(doc["payload"])), **payload_changes}
    doc["payload"] = base64.b64encode(json.dumps(payload).encode()).decode()
    return json.dumps(doc).encode()


def test_a_bundle_signed_by_a_trusted_key_is_accepted() -> None:
    p = policy.verify(bundle(version=7), TRUSTED, tenant="acme")
    assert (p.tenant, p.version, p.key_id) == ("acme", 7, next(iter(TRUSTED)))
    # The custom rule is first, ahead of the built-in rules it extends.
    assert next(iter(p.rules)) == "*loyalty_number*"


@pytest.mark.parametrize(
    ("data", "kwargs", "reason"),
    [
        (b"not json", {}, "not a well-formed"),
        (b'{"schema": "safestream.policy/v9"}', {}, "unsupported bundle schema"),
        (b'{"schema": "safestream.policy/v1", "payload": "%%%", "signatures": []}', {}, "well-f"),
        (bundle(key=OTHER_KEY), {}, "not signed by a trusted key"),
        # Rules weakened after signing: the signature no longer matches.
        (edited(bundle(), field_rules={"mode": "replace", "rules": {"x": "secret"}}), {}, "verify"),
        (edited(bundle(version=1), version=99), {}, "does not verify"),
        (bundle(tenant="globex"), {"tenant": "acme"}, "another tenant"),
        (bundle(version=3), {"min_version": 5}, "below the minimum 5"),
    ],
)
def test_refusals(data: bytes, kwargs: dict[str, Any], reason: str) -> None:
    with pytest.raises(PolicyError, match=reason):
        policy.verify(data, TRUSTED, **kwargs)


def test_rollback_and_replay_of_the_same_version_are_refused() -> None:
    current = policy.verify(bundle(version=5), TRUSTED)
    for older in (4, 5):
        with pytest.raises(PolicyError, match="not newer than version 5"):
            policy.verify(bundle(version=older), TRUSTED, current=current)
    assert policy.verify(bundle(version=6), TRUSTED, current=current).version == 6


def test_a_validly_signed_bundle_with_unusable_rules_is_refused_without_quoting_them() -> None:
    # Signed directly, bypassing sign()'s own validation, as a buggy signer might.
    payload = json.dumps(
        {"tenant": "acme", "version": 1, "field_rules": {"rules": {"re:([unclosed": "secret"}}}
    ).encode()
    data = json.dumps(
        {
            "schema": policy.SCHEMA,
            "payload": base64.b64encode(payload).decode(),
            "signatures": [
                {
                    "key_id": next(iter(TRUSTED)),
                    "algorithm": "ed25519",
                    "signature": base64.b64encode(KEY.sign(payload)).decode(),
                }
            ],
        }
    ).encode()
    with pytest.raises(PolicyError) as refused:
        policy.verify(data, TRUSTED)
    assert "invalid" in str(refused.value) and "unclosed" not in str(refused.value)


def test_sign_refuses_rules_no_connector_would_accept() -> None:
    with pytest.raises(ValueError):
        policy.sign({"rules": {"*x*": "not_an_entity_type"}}, KEY, "acme", 1)
    with pytest.raises(ValueError):
        policy.sign(RULES, KEY, "acme", 0)


def test_key_rotation_either_signature_is_enough() -> None:
    doc = json.loads(bundle(key=OTHER_KEY))
    doc["signatures"] += json.loads(bundle())["signatures"]  # payloads differ: issued_at
    # A second signature over the *same* payload, as rotation produces:
    payload = base64.b64decode(doc["payload"])
    doc["signatures"][1]["signature"] = base64.b64encode(KEY.sign(payload)).decode()
    assert policy.verify(json.dumps(doc).encode(), TRUSTED).key_id == next(iter(TRUSTED))


def test_cli_keygen_sign_verify_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    key, rules, out = tmp_path / "signing.key", tmp_path / "rules.json", tmp_path / "policy.json"
    rules.write_text(json.dumps(RULES))
    assert policy.main(["keygen", str(key)]) == 0
    public = json.loads(capsys.readouterr().out)["public_key"]
    assert key.stat().st_mode & 0o777 == 0o600
    assert policy.main(["keygen", str(key)]) == 1  # never overwrites a key
    capsys.readouterr()
    sign = ["sign", str(rules), "--key", str(key), "--tenant", "acme", "--version", "2"]
    assert policy.main([*sign, "-o", str(out)]) == 0
    capsys.readouterr()
    assert policy.main(["verify", str(out), "--public-key", public]) == 0
    assert json.loads(capsys.readouterr().out)["version"] == 2
    assert policy.main(["verify", str(out), "--public-key", public, "--min-version", "3"]) == 1
    assert "below the minimum" in capsys.readouterr().err


# ----------------------------------------------------------------------
# the connector: adopt newer, keep what is in force when refused
# ----------------------------------------------------------------------


class Idle:
    """Stands in for consumer and producer: the reload path touches neither."""


def connector(path: Path) -> KafkaRedactionConnector:
    source = PolicySource(path, TRUSTED, tenant="acme")
    current = source.load()
    assert current is not None
    config = ConnectorConfig(
        bootstrap_servers="x",
        policy_file=path,
        policy_public_keys=policy.encode_public_key(KEY.public_key()),
    )
    conn = KafkaRedactionConnector(
        config,
        StructuredRedactor(field_rules=current.rules),
        Idle(),  # type: ignore[arg-type]
        Idle(),  # type: ignore[arg-type]
        source,
        current,
    )
    conn._policy_due = 0.0  # check the file on the next call
    return conn


def redacts(conn: KafkaRedactionConnector, record: str) -> str:
    return conn.redactor.redact_line(record).text


def test_connector_adopts_a_newer_bundle_and_keeps_the_old_one_when_refused(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(bundle(version=1, rules={"mode": "extend", "rules": {}}))
    conn = connector(path)
    record = '{"loyalty_number":"L-4242-77"}'
    assert redacts(conn, record) == record  # version 1 has no rule for it

    path.write_bytes(bundle(version=2))  # adds the loyalty_number rule
    conn._maybe_reload_policy()
    assert conn.policy is not None and conn.policy.version == 2
    assert redacts(conn, record) == '{"loyalty_number":"[REDACTED]"}'
    assert conn.snapshot().policy_version == 2

    for refused in (
        bundle(version=3, key=OTHER_KEY, rules={"mode": "extend", "rules": {}}),  # untrusted
        bundle(version=1, rules={"mode": "extend", "rules": {}}),  # rollback
        b"garbage",
    ):
        path.write_bytes(refused)
        conn._policy_due = 0.0
        conn._maybe_reload_policy()
        # Still version 2, still redacting.
        assert conn.policy.version == 2
        assert redacts(conn, record) == '{"loyalty_number":"[REDACTED]"}'
    assert conn.policy_rejections == 3
    assert "policy bundle refused" in caplog.text and "loyalty" not in caplog.text


def test_unchanged_file_is_not_reloaded_or_counted(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(bundle(version=1))
    conn = connector(path)
    before = conn.redactor
    conn._maybe_reload_policy()
    assert conn.redactor is before and conn.policy_rejections == 0


def test_policy_configuration_is_all_or_nothing() -> None:
    key = policy.encode_public_key(KEY.public_key())
    for bad in (
        {"policy_file": "p.json"},  # no key to trust
        {"policy_public_keys": key},  # nothing to verify
        {"policy_file": "p.json", "policy_public_keys": key, "field_rules_file": "r.json"},
    ):
        with pytest.raises(ValueError):
            ConnectorConfig(bootstrap_servers="x", **bad)  # type: ignore[arg-type]


def test_policy_dataclass_is_what_audit_events_report(tmp_path: Path) -> None:
    path = tmp_path / "policy.json"
    path.write_bytes(bundle(version=4))
    conn = connector(path)
    snap = conn.snapshot()
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)
    event = conn.audit_event(snap, snap, now, now, final=False)
    assert event["policy"] == {"tenant": "acme", "version": 4, "key_id": next(iter(TRUSTED))}
    assert isinstance(conn.policy, Policy)


def test_batch_runs_on_a_verified_bundle_and_refuses_an_untrusted_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from safestream_enterprise import batch

    src, signed = tmp_path / "in.ndjson", tmp_path / "policy.json"
    src.write_text('{"loyalty_number":"L-4242-77"}\n')
    signed.write_bytes(bundle(version=1))
    monkeypatch.setenv("SAFESTREAM_POLICY_PUBLIC_KEYS", policy.encode_public_key(KEY.public_key()))
    monkeypatch.setattr("sys.stdin", None)
    out = tmp_path / "out.ndjson"
    assert batch.main([str(src), "-o", str(out), "--policy", str(signed)]) == 0
    assert out.read_text() == '{"loyalty_number":"[REDACTED]"}\n'

    signed.write_bytes(bundle(version=2, key=OTHER_KEY))
    assert batch.main([str(src), "-o", str(tmp_path / "o2"), "--policy", str(signed)]) == 2
    assert not (tmp_path / "o2").exists()
