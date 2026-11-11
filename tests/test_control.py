"""The control-plane uplink: client behaviour, connector wiring, and the
promise that nothing but content-free audit events ever leaves the process."""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from safestream_enterprise import control, policy
from safestream_enterprise.connectors.health import render_metrics
from safestream_enterprise.connectors.kafka import (
    ConnectorConfig,
    KafkaRedactionConnector,
    build_redactor,
    connect_control,
    load_policy,
)
from safestream_enterprise.control import ControlClient, ControlError, Response
from test_kafka import FakeConsumer, FakeMsg, FakeProducer

KEY = Ed25519PrivateKey.generate()
PUBLIC = policy.encode_public_key(KEY.public_key())
URL = "https://api.safestreamdata.test"
TOKEN = "sst_agent_test-token-not-real"
LOYALTY = {"*loyalty_number*": "id_number"}
PII = b'{"loyalty_number":"L-4242-77","email":"bob@corp.example","note":"call 415-555-0132"}'
PII_VALUES = (b"L-4242-77", b"bob@corp.example", b"415-555-0132", b"bob")


def signed(version: int, rules: dict[str, str] | None = None, tenant: str = "acme") -> bytes:
    return policy.sign({"rules": rules or {}}, KEY, tenant, version)


class FakeControlPlane:
    """The Worker's agent routes, in memory. Records every request it is sent."""

    def __init__(self) -> None:
        self.tenant = "acme"
        self.bundles: dict[str, bytes | None] = {"active": signed(1), "candidate": None}
        self.requests: list[dict[str, Any]] = []
        self.telemetry: list[bytes] = []
        #: Status to answer the next requests with, regardless of route.
        self.fail_with: list[int | type[OSError]] = []

    def __call__(
        self, method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> Response:
        self.requests.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        assert url.startswith(URL)
        assert headers["authorization"] == f"Bearer {TOKEN}"
        if self.fail_with:
            failure = self.fail_with.pop(0)
            if isinstance(failure, type):
                raise failure("simulated")
            return Response(failure, {}, b'{"error":"x"}')
        route = url[len(URL) :]
        if route == "/v1/agent/whoami":
            return Response(200, {}, json.dumps({"tenant": self.tenant, "label": "prod"}).encode())
        if route.startswith("/v1/agent/policy/"):
            which = route.rsplit("/", 1)[1]
            data = self.bundles[which]
            if data is None:
                return Response(404, {}, b"{}")
            etag = f'"{hash(data)}"'
            if headers.get("if-none-match") == etag:
                return Response(304, {"ETag": etag}, b"")
            return Response(200, {"ETag": etag}, data)
        if route == "/v1/agent/telemetry" and method == "POST":
            assert body is not None
            self.telemetry.append(body)
            return Response(202, {}, b'{"accepted":true}')
        return Response(404, {}, b"{}")


def client(cp: FakeControlPlane, **kw: Any) -> ControlClient:
    return ControlClient(URL, TOKEN, "pod-a", transport=cp, **kw)


# ----------------------------------------------------------------------
# client
# ----------------------------------------------------------------------


def test_policies_are_downloaded_once_and_then_only_revalidated() -> None:
    cp = FakeControlPlane()
    c = client(cp)
    c.refresh()
    assert c.active_bundle() == cp.bundles["active"] and c.candidate_bundle() is None
    c.refresh()
    # Second round: conditional, so an unchanged bundle costs no body.
    assert cp.requests[2]["headers"]["if-none-match"]
    assert cp.requests[2]["headers"][control.INSTANCE_HEADER] == "pod-a"

    cp.bundles["candidate"] = signed(2, LOYALTY)
    c.refresh()
    assert c.candidate_bundle() == cp.bundles["candidate"]
    cp.bundles["candidate"] = None  # withdrawn
    c.refresh()
    assert c.candidate_bundle() is None


def test_an_unreachable_control_plane_keeps_what_was_downloaded() -> None:
    cp = FakeControlPlane()
    c = client(cp)
    c.refresh()
    before = c.active_bundle()
    for failure in (OSError, 503, 401, 429):
        cp.fail_with = [failure]
        with pytest.raises(ControlError) as caught:
            c.refresh()
        assert TOKEN not in str(caught.value)
        assert c.active_bundle() == before
    assert c.status().requests_failed == 4


def test_audit_events_are_delivered_in_order_and_survive_an_outage() -> None:
    cp = FakeControlPlane()
    c = client(cp)
    for n in range(3):
        c.enqueue(b'{"n":%d}' % n)
    cp.fail_with = [OSError]
    assert c.deliver() == 0 and c.status().queue_depth == 3
    assert c.deliver() == 3
    assert cp.telemetry == [b'{"n":0}', b'{"n":1}', b'{"n":2}']
    assert c.status().telemetry_sent == 3 and c.status().queue_depth == 0


def test_an_event_refused_for_good_is_dropped_not_retried_forever() -> None:
    cp = FakeControlPlane()
    c = client(cp)
    c.enqueue(b'{"n":0}')
    c.enqueue(b'{"n":1}')
    cp.fail_with = [409]  # does not extend the anchored chain
    assert c.deliver() == 1
    assert cp.telemetry == [b'{"n":1}']
    assert c.status().telemetry_rejected == 1


def test_a_full_queue_drops_the_oldest_event() -> None:
    c = client(FakeControlPlane(), queue_max=2)
    for n in range(3):
        c.enqueue(b"%d" % n)
    status = c.status()
    assert (status.queue_depth, status.telemetry_dropped) == (2, 1)


def test_connected_reflects_recent_success() -> None:
    now = [100.0]
    c = client(FakeControlPlane(), clock=lambda: now[0], poll_s=30)
    assert not c.status().connected
    c.refresh()
    assert c.status().connected
    now[0] += 200
    assert not c.status().connected


def test_thread_delivers_and_stop_flushes_the_queue() -> None:
    cp = FakeControlPlane()
    c = client(cp, poll_s=1).start()
    c.enqueue(b'{"final":true}')
    c.stop(5)
    assert cp.telemetry == [b'{"final":true}']


@pytest.mark.parametrize(
    "url",
    [
        "http://api.safestreamdata.com",
        "ftp://api.safestreamdata.com",
        "https://user@api.safestreamdata.com",
        "https://api.safestreamdata.com/?x=1",
        "https://",
    ],
)
def test_only_https_base_urls(url: str) -> None:
    with pytest.raises(ValueError):
        control.validate_url(url)


def test_plain_http_only_to_this_machine() -> None:
    assert control.validate_url("http://127.0.0.1:8787/") == "http://127.0.0.1:8787"
    assert (
        control.validate_url("https://api.safestreamdata.com") == "https://api.safestreamdata.com"
    )


def test_real_transport_never_follows_a_redirect() -> None:
    """A redirect would hand the token to whatever host it names."""
    seen: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/steal")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}"
        c = ControlClient(url, TOKEN, "pod-a", transport=control.urllib_transport())
        # The proxy settings of the test machine must not apply to loopback.
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("NO_PROXY", "*")
            with pytest.raises(ControlError, match="302"):
                c.whoami()
    finally:
        server.shutdown()
    assert seen == ["/v1/agent/whoami"]


# ----------------------------------------------------------------------
# what may leave the process
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("event", "where"),
    [
        ({"instance": "bob@corp.example"}, "instance"),
        ({"note": "anything"}, "note"),
        ({"redactions": {"Bob Smith": 1}}, "redactions"),
        ({"redactions": {"email": "1"}}, "redactions.email"),
        ({"topics": {"ingress": ["a"]}}, "topics.ingress"),
        ({"records": {"egress": 1.5}}, "records.egress"),
        ({"chain": {"prev": "sha256:not-a-hash"}}, "chain.prev"),
    ],
)
def test_content_check_refuses_free_text_anywhere(event: dict[str, Any], where: str) -> None:
    with pytest.raises(ValueError, match=where.replace(".", r"\.")):
        control.check_content_free(event)


# ----------------------------------------------------------------------
# the connector with a control plane
# ----------------------------------------------------------------------


def control_config(tmp_path: Path, **kw: Any) -> ConnectorConfig:
    return ConnectorConfig(
        bootstrap_servers="x",
        control_url=URL,
        control_token=TOKEN,  # type: ignore[arg-type]
        policy_public_keys=PUBLIC,
        **kw,
    )


def connector(
    cp: FakeControlPlane, cfg: ConnectorConfig
) -> tuple[KafkaRedactionConnector, FakeProducer]:
    c, tenant = connect_control(cfg, transport=cp, sleep=lambda _s: None)
    source, verified = load_policy(cfg, c, tenant)
    producer = FakeProducer()
    conn = KafkaRedactionConnector(
        cfg,
        build_redactor(cfg, verified),
        FakeConsumer(),  # type: ignore[arg-type]
        producer,  # type: ignore[arg-type]
        source,
        verified,
        c,
    )
    return conn, producer


def tick(conn: KafkaRedactionConnector, records: int = 1) -> None:
    """One main-loop iteration: a batch, then the between-batch work."""
    conn.process_batch([FakeMsg(PII, offset=i) for i in range(records)])  # type: ignore[misc]
    conn._policy_due = 0.0
    conn._maybe_reload_policy()
    conn._canary_due = 0.0
    conn._maybe_canary()
    conn._audit_due = 0.0
    conn._maybe_audit()


def test_policy_and_candidate_come_from_the_control_plane(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    conn, producer = connector(cp, control_config(tmp_path))
    assert conn.policy is not None and conn.policy.version == 1

    cp.bundles["candidate"] = signed(2, LOYALTY)
    assert conn.control is not None
    conn.control.refresh()
    tick(conn)
    assert conn.shadow is not None and conn.shadow.policy.version == 2

    cp.bundles["active"] = cp.bundles["candidate"]  # promoted
    conn.control.refresh()
    tick(conn)
    assert conn.policy.version == 2 and conn.shadow is None
    tick(conn)  # the next batch is redacted under version 2
    assert json.loads(producer.sent[-1]["value"])["loyalty_number"] == "[REDACTED]"


def test_a_new_bundle_applies_on_the_next_loop_not_the_next_reload_tick(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    conn, _ = connector(cp, control_config(tmp_path, policy_reload_s=3600))
    conn._maybe_reload_policy()  # first iteration: due anyway
    cp.bundles["active"] = signed(2, LOYALTY)
    assert conn.control is not None
    conn.control.refresh()
    conn._maybe_reload_policy()  # reload tick is an hour away; the download is not
    assert conn.policy is not None and conn.policy.version == 2
    conn.control.refresh()  # unchanged (304): nothing to do
    generation = conn.control.generation
    conn._maybe_reload_policy()
    assert conn.control.generation == generation


@pytest.mark.parametrize(
    "bad",
    [
        lambda: policy.sign({"rules": {}}, Ed25519PrivateKey.generate(), "acme", 5),  # forged
        lambda: signed(5, tenant="globex"),  # another tenant's
        lambda: signed(1),  # a rollback (same version again)
    ],
)
def test_the_control_plane_cannot_weaken_or_roll_back_the_policy(tmp_path: Path, bad: Any) -> None:
    cp = FakeControlPlane()
    cp.bundles["active"] = signed(3, LOYALTY)
    conn, producer = connector(cp, control_config(tmp_path))
    cp.bundles["active"] = bad()
    assert conn.control is not None
    conn.control.refresh()
    tick(conn)
    assert conn.policy is not None and conn.policy.version == 3
    assert conn.policy_rejections == 1
    assert json.loads(producer.sent[0]["value"])["loyalty_number"] == "[REDACTED]"


def test_nothing_but_content_free_audit_events_leaves_the_process(tmp_path: Path) -> None:
    """The contract: whatever the records contain, the uplink carries none of it."""
    cp = FakeControlPlane()
    cp.bundles["candidate"] = signed(2, LOYALTY)
    conn, _ = connector(cp, control_config(tmp_path))
    assert conn.control is not None
    for _ in range(3):
        tick(conn, records=5)
        conn.control.refresh()
        conn.control.deliver()
    conn._maybe_audit(final=True)
    conn.control.deliver()

    # Four windows, plus the one closed early when shadow evaluation began.
    assert len(cp.telemetry) == 5
    uplinked = b"".join((r["body"] or b"") + json.dumps(r["headers"]).encode() for r in cp.requests)
    uplinked += b"".join(r["url"].encode() for r in cp.requests)
    for value in PII_VALUES:
        assert value not in uplinked
    posts = [r for r in cp.requests if r["method"] != "GET"]
    assert {r["url"] for r in posts} == {URL + "/v1/agent/telemetry"}
    for body in cp.telemetry:
        control.check_content_free(json.loads(body))
    # The events are the hash chain, byte for byte: anchoring them anchors it.
    links = [json.loads(e)["chain"] for e in cp.telemetry]
    assert [link["seq"] for link in links] == [0, 1, 2, 3, 4]
    events = [json.loads(e) for e in cp.telemetry]
    assert sum(e["records"]["egress"] for e in events) == 15
    assert sum(e["canary"]["checks"] for e in events) == 6
    assert sum(e["canary"]["leaks"] for e in events) == 0
    assert events[-1]["shadow"]["candidate"]["version"] == 2


def test_with_an_audit_topic_too_the_topic_is_the_record_and_the_uplink_a_copy(
    tmp_path: Path,
) -> None:
    cp = FakeControlPlane()
    conn, producer = connector(cp, control_config(tmp_path, audit_topic="safestream-audit"))
    tick(conn)
    assert conn.control is not None
    conn.control.deliver()
    published = [m["value"] for m in producer.sent if m["topic"] == "safestream-audit"]
    assert published == cp.telemetry and len(published) == 1


def test_an_event_that_is_not_content_free_stays_local(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    conn, _ = connector(cp, control_config(tmp_path, audit_topic="safestream-audit"))
    conn.instance = "bob@corp.example"  # a hostname no allow-list would pass
    tick(conn)
    assert conn.control is not None
    assert conn.control.status().queue_depth == 0 and conn.audit_events == 1


def test_startup_retries_then_starts_on_the_bootstrap_file(tmp_path: Path) -> None:
    bootstrap = tmp_path / "policy.json"
    bootstrap.write_bytes(signed(4))
    cp = FakeControlPlane()
    cp.fail_with = [OSError] * 100
    cfg = control_config(tmp_path, policy_file=bootstrap, control_startup_timeout_s=0)
    conn, _ = connector(cp, cfg)
    assert conn.policy is not None and conn.policy.version == 4
    # Once the control plane answers, a newer version is adopted from it.
    cp.fail_with = []
    cp.bundles["active"] = signed(5)
    assert conn.control is not None
    conn.control.refresh()
    tick(conn)
    assert conn.policy.version == 5


def test_startup_without_a_bootstrap_file_fails_closed(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    cp.fail_with = [503] * 100
    with pytest.raises(ControlError):
        cfg = control_config(tmp_path, control_startup_timeout_s=0)
        connect_control(cfg, transport=cp, sleep=lambda _: None)
    cp.fail_with = []
    cp.bundles["active"] = None  # reachable, but nothing promoted yet
    cfg = control_config(tmp_path)
    c, tenant = connect_control(cfg, transport=cp)
    with pytest.raises(policy.PolicyError, match="no active policy"):
        load_policy(cfg, c, tenant)


def test_a_token_for_another_tenant_is_a_configuration_error(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    cp.tenant = "globex"
    with pytest.raises(ValueError, match="globex"):
        connect_control(control_config(tmp_path, policy_tenant="acme"), transport=cp)


def test_the_token_tenant_is_enforced_on_bundles(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    cp.bundles["active"] = signed(1, tenant="globex")  # signed by a trusted key, wrong tenant
    cfg = control_config(tmp_path)
    c, tenant = connect_control(cfg, transport=cp)
    with pytest.raises(policy.PolicyError, match="another tenant"):
        load_policy(cfg, c, tenant)


def test_uplink_metrics(tmp_path: Path) -> None:
    cp = FakeControlPlane()
    conn, _ = connector(cp, control_config(tmp_path))
    tick(conn)
    text = render_metrics(conn.snapshot(), 0.0)
    assert "safestream_control_connected 1" in text
    assert "safestream_control_queue_depth 1" in text
    assert 'safestream_control_telemetry_total{outcome="accepted"} 0' in text


@pytest.mark.parametrize(
    ("kw", "message"),
    [
        ({"control_url": URL}, "set together"),
        ({"control_token": TOKEN}, "set together"),
        ({"control_url": "http://api.safestreamdata.com", "control_token": TOKEN}, "https"),
        ({"control_url": URL, "control_token": TOKEN}, "PUBLIC_KEYS"),
        (
            {
                "control_url": URL,
                "control_token": TOKEN,
                "policy_public_keys": PUBLIC,
                "field_rules_file": "rules.json",
            },
            "not both",
        ),
        (
            {
                "control_url": URL,
                "control_token": TOKEN,
                "policy_public_keys": PUBLIC,
                "policy_file": "p.json",
                "shadow_policy_file": "c.json",
            },
            "candidate comes from the control plane",
        ),
    ],
)
def test_configuration_is_checked(kw: dict[str, Any], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        ConnectorConfig(bootstrap_servers="x", **kw)


def test_air_gapped_by_default() -> None:
    """No control settings: no client, no uplink metrics, nothing but Kafka."""
    cfg = ConnectorConfig.from_env({"KAFKA_BOOTSTRAP_SERVERS": "x"})
    assert cfg.control_url is None and not cfg.auditing
    conn = KafkaRedactionConnector(
        cfg,
        build_redactor(cfg),
        FakeConsumer(),  # type: ignore[arg-type]
        FakeProducer(),  # type: ignore[arg-type]
    )
    assert conn.control is None
    conn._audit_due = 0.0
    conn._maybe_audit()
    assert conn.audit_events == 0
    assert "safestream_control" not in render_metrics(conn.snapshot(), 0.0)


def test_main_never_contacts_a_control_plane_when_none_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from safestream_enterprise.connectors import kafka

    called: list[object] = []
    monkeypatch.setattr(kafka, "connect_control", lambda *a, **k: called.append(a))
    monkeypatch.setattr(kafka, "Consumer", lambda _c: (_ for _ in ()).throw(SystemExit(9)))
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS", "x")
    monkeypatch.setenv("SAFESTREAM_METRICS_PORT", "0")
    with pytest.raises(SystemExit):
        kafka.main()
    assert called == []


def test_from_env_reads_the_control_settings() -> None:
    cfg = ConnectorConfig.from_env(
        {
            "KAFKA_BOOTSTRAP_SERVERS": "x",
            "SAFESTREAM_CONTROL_URL": URL,
            "SAFESTREAM_CONTROL_TOKEN": TOKEN,
            "SAFESTREAM_POLICY_PUBLIC_KEYS": PUBLIC,
            "SAFESTREAM_CONTROL_POLL_S": "15",
            "SAFESTREAM_CANARY_INTERVAL_S": "0",
            "SAFESTREAM_CANARY_ON_LEAK": "stop",
        }
    )
    assert (cfg.control_url, cfg.control_poll_s, cfg.canary_interval_s) == (URL, 15, 0)
    assert cfg.canary_on_leak == "stop" and cfg.auditing
    assert TOKEN not in repr(cfg)


# ----------------------------------------------------------------------
# safestream-control check
# ----------------------------------------------------------------------


def test_cli_check(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    cp = FakeControlPlane()
    cp.bundles["candidate"] = signed(2, LOYALTY)
    monkeypatch.setenv("SAFESTREAM_CONTROL_URL", URL)
    monkeypatch.setenv("SAFESTREAM_CONTROL_TOKEN", TOKEN)
    monkeypatch.setenv("SAFESTREAM_POLICY_PUBLIC_KEYS", PUBLIC)
    assert control.main(["check"], transport=cp) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["ok"] and report["tenant"] == "acme"
    assert report["active"]["version"] == 1 and report["candidate"]["version"] == 2
    assert TOKEN not in json.dumps(report)

    cp.bundles["active"] = policy.sign({"rules": {}}, Ed25519PrivateKey.generate(), "acme", 9)
    assert control.main(["check"], transport=cp) == 1
    assert "not signed by a trusted key" in json.loads(capsys.readouterr().out)["error"]

    cp.bundles["active"] = None
    assert control.main(["check"], transport=cp) == 0
    assert "no active policy" in json.loads(capsys.readouterr().out)["warning"]

    monkeypatch.delenv("SAFESTREAM_CONTROL_TOKEN")
    assert control.main(["check"], transport=cp) == 2
