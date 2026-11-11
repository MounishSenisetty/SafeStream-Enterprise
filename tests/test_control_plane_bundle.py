"""A policy bundle signed by the control plane (TypeScript, WebCrypto) must be
accepted by the connector (this package). The fixture is produced by the
Worker's signing code with a fixed test key; control-plane/test/api.test.ts
asserts the Worker still produces exactly these bytes."""

from __future__ import annotations

import json
from pathlib import Path

from safestream_enterprise import policy

FIXTURES = Path(__file__).resolve().parent.parent / "control-plane/test/fixtures"


def test_connector_verifies_a_bundle_signed_by_the_control_plane() -> None:
    key = json.loads((FIXTURES / "signing-key.json").read_text())
    trusted = policy.parse_public_keys(key["public_key"])
    # Both sides derive the same id for the same key.
    assert list(trusted) == [key["key_id"]]

    verified = policy.verify(
        (FIXTURES / "policy-bundle.json").read_bytes(), trusted, tenant="acme", min_version=7
    )
    assert (verified.tenant, verified.version, verified.key_id) == ("acme", 7, key["key_id"])
    assert next(iter(verified.rules)) == "*loyalty_number*"
