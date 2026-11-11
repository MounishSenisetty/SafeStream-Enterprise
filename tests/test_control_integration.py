"""The connector against the real control plane.

Skipped unless ``SAFESTREAM_IT_CONTROL_URL`` names a running Worker and
``SAFESTREAM_IT_PLATFORM_TOKEN`` its platform admin token. CI runs the Worker
with ``wrangler dev`` (local D1 and R2, nothing touches Cloudflare):

    cd control-plane
    npx wrangler d1 migrations apply DB --local --env staging
    npx wrangler dev --env staging --local --port 8787 --env-file <file with the two secrets>

Kafka is the in-memory fake here: the broker paths have their own integration
tests, and this one is about the HTTP contract, end to end: enrollment,
policy pull and verification, shadow evaluation, audit anchoring, a staged
rollout driven by the connector's own reports, and offline verification of
the chain against the head the control plane anchored.
"""

from __future__ import annotations

import base64
import json
import os
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any

import pytest

from safestream_enterprise import audit
from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    KafkaRedactionConnector,
    build_redactor,
    connect_control,
    load_policy,
)
from safestream_enterprise.control import ControlError
from test_kafka import FakeConsumer, FakeMsg, FakeProducer

URL = os.environ.get("SAFESTREAM_IT_CONTROL_URL", "")
PLATFORM_TOKEN = os.environ.get("SAFESTREAM_IT_PLATFORM_TOKEN", "")
pytestmark = pytest.mark.skipif(
    not (URL and PLATFORM_TOKEN), reason="SAFESTREAM_IT_CONTROL_URL not set"
)

RECORD = b'{"loyalty_number":"L-4242-77","email":"bob@corp.example"}'
LOYALTY = {"mode": "extend", "rules": {"*loyalty_number*": "id_number"}}


def api(method: str, path: str, token: str, body: Any = None) -> tuple[int, Any]:
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        URL + path, data=data, method=method, headers={"authorization": f"Bearer {token}"}
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # loopback
    try:
        with opener.open(request, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"null")


@pytest.fixture
def no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    # The connector's own transport honours HTTPS_PROXY; the Worker is local.
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")


def test_enroll_pull_shadow_anchor_and_roll_out(tmp_path: Path, no_proxy: None) -> None:
    tenant_id = f"it-{uuid.uuid4().hex[:10]}"
    new_tenant = {"id": tenant_id, "name": "IT"}
    status, tenant = api("POST", "/v1/admin/tenants", PLATFORM_TOKEN, new_tenant)
    assert status == 201
    admin = tenant["admin_token"]
    status, agent = api("POST", "/v1/agent-tokens", admin, {"label": "integration"})
    assert status == 201
    assert api("POST", "/v1/policies", admin, {"field_rules": {"rules": {}}})[0] == 201
    assert api("POST", "/v1/policies/1/promote", admin, {"strategy": "immediate"})[0] == 200

    # Enrollment is configuration: URL, token, and the key to trust.
    cfg = ConnectorConfig(
        bootstrap_servers="x",
        control_url=URL,
        control_token=agent["token"],
        policy_public_keys=agent["public_key"],
        control_startup_timeout_s=5,
        # The fake producer keeps a copy of each event, to verify offline.
        audit_topic="safestream-audit",
    )
    client, token_tenant = connect_control(cfg)
    assert token_tenant == tenant_id
    source, verified = load_policy(cfg, client, token_tenant)
    assert verified is not None and verified.version == 1
    producer = FakeProducer()
    conn = KafkaRedactionConnector(
        cfg,
        build_redactor(cfg, verified),
        FakeConsumer(),  # type: ignore[arg-type]
        producer,  # type: ignore[arg-type]
        source,
        verified,
        client,
    )
    conn.instance = client.instance = f"it-pod-{uuid.uuid4().hex[:6]}"
    conn._chain_id = f"{conn.instance}-chain"

    def tick() -> None:
        conn.process_batch([FakeMsg(RECORD, offset=0)])  # type: ignore[list-item]
        client.refresh()
        conn._policy_due = conn._canary_due = conn._audit_due = 0.0
        conn._maybe_reload_policy()
        conn._maybe_canary()
        conn._maybe_audit()
        client.deliver()
        assert client.status().queue_depth == 0

    tick()
    egress = lambda: [m for m in producer.sent if m["topic"] == "egress-logs-clean"]  # noqa: E731
    assert json.loads(egress()[-1]["value"])["loyalty_number"] == "L-4242-77"

    # Version 2 is published: the connector evaluates it in shadow, publishes v1.
    assert api("POST", "/v1/policies", admin, {"field_rules": LOYALTY})[0] == 201
    tick()
    assert conn.shadow is not None and conn.shadow.policy.version == 2
    tick()
    assert json.loads(egress()[-1]["value"])["loyalty_number"] == "L-4242-77"
    status, agents = api("GET", "/v1/agents", admin)
    (me,) = agents["agents"]
    assert me["instance"] == conn.instance and me["shadow_version"] == 2
    assert me["canary_leaks"] == 0 and me["canary_checks"] >= 2

    # Staged rollout: this connector is the whole fleet, so the first stage.
    status, promoted = api("POST", "/v1/policies/2/promote", admin, {"soak_seconds": 0})
    assert (status, promoted["state"]) == (200, "rolling_out")
    tick()  # adopts version 2 and reports a window under it: first stage done
    assert conn.policy is not None and conn.policy.version == 2
    tick()  # reports again under the second stage: rollout complete
    status, policies = api("GET", "/v1/policies", admin)
    assert (policies["active_version"], policies["rollout"]) == (2, None)
    conn.process_batch([FakeMsg(RECORD, offset=1)])  # type: ignore[list-item]
    assert json.loads(egress()[-1]["value"])["loyalty_number"] == "[REDACTED]"

    # Offline verification against the head the control plane anchored.
    conn._maybe_audit(final=True)
    client.deliver()
    events = [m["value"] for m in producer.sent if m["topic"] == "safestream-audit"]
    status, chains = api("GET", "/v1/chains", admin)
    (chain,) = chains["chains"]
    assert chain["chain"] == conn._chain_id and not chain["broken"] and chain["closed"]
    found, _ = audit.verify(events)
    assert found[0].problems == [] and chain["head"] in found[0].hashes


def test_a_revoked_token_cuts_the_connector_off(tmp_path: Path, no_proxy: None) -> None:
    tenant_id = f"it-{uuid.uuid4().hex[:10]}"
    _, tenant = api("POST", "/v1/admin/tenants", PLATFORM_TOKEN, {"id": tenant_id, "name": "IT"})
    _, agent = api("POST", "/v1/agent-tokens", tenant["admin_token"], {"label": "revoke-me"})
    assert api("POST", f"/v1/tokens/{agent['id']}/revoke", tenant["admin_token"])[0] == 200
    cfg = ConnectorConfig(
        bootstrap_servers="x",
        control_url=URL,
        control_token=agent["token"],
        policy_public_keys=base64.b64encode(b"\x01" * 32).decode(),
        control_startup_timeout_s=0,
    )
    with pytest.raises(ControlError, match="401"):
        connect_control(cfg)
