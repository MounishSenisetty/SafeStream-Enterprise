import urllib.error
import urllib.request

import pytest

from safestream_enterprise.connectors.health import (
    ConnectorMetrics,
    HealthServer,
    dispatch,
    render_metrics,
)

M = ConnectorMetrics(
    ready=True,
    heartbeat=100.0,
    egress_records=7,
    dlq_records=2,
    batches=3,
    transaction_aborts=1,
    redactions={"secret": 4, "email": 5},
)


def test_liveness_follows_the_heartbeat() -> None:
    assert dispatch("GET", "/healthz", M, now=150.0, liveness_timeout_s=120)[0] == 200
    status, _, body = dispatch("GET", "/healthz", M, now=221.0, liveness_timeout_s=120)
    assert status == 503 and "stalled for 121s" in body


def test_readiness() -> None:
    assert dispatch("GET", "/readyz", M, 100.0, 120)[0] == 200
    assert dispatch("GET", "/readyz", M._replace(ready=False), 100.0, 120)[0] == 503


def test_metrics_exposition() -> None:
    status, ctype, body = dispatch("GET", "/metrics?x=1", M, now=102.5, liveness_timeout_s=120)
    assert status == 200 and ctype.startswith("text/plain; version=0.0.4")
    assert body == render_metrics(M, 102.5)
    for line in (
        'safestream_records_total{destination="egress"} 7',
        'safestream_records_total{destination="dlq"} 2',
        'safestream_redactions_total{entity_type="email"} 5',
        'safestream_redactions_total{entity_type="secret"} 4',
        "safestream_batches_total 3",
        "safestream_transaction_aborts_total 1",
        "safestream_heartbeat_age_seconds 2.500",
        "safestream_ready 1",
    ):
        assert line in body.splitlines()
    # every sample has HELP/TYPE metadata and the body ends with a newline
    assert body.endswith("\n") and body.count("# TYPE") == 8


def test_unknown_routes_and_methods() -> None:
    assert dispatch("GET", "/nope", M, 100.0, 120)[0] == 404
    assert dispatch("POST", "/metrics", M, 100.0, 120)[0] == 405


def _get(port: int, path: str) -> tuple[int, str]:
    # bypass any HTTP(S)_PROXY in the environment: this is loopback
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def test_server_serves_probes_and_metrics_over_http() -> None:
    state = {"m": M}
    clock = {"now": 101.0}
    server = HealthServer(
        lambda: state["m"],
        port=0,
        liveness_timeout_s=120,
        host="127.0.0.1",
        clock=lambda: clock["now"],
    ).start()
    try:
        assert _get(server.port, "/healthz") == (200, "ok\n")
        assert _get(server.port, "/readyz") == (200, "ready\n")
        status, body = _get(server.port, "/metrics")
        assert status == 200 and 'safestream_records_total{destination="egress"} 7' in body
        # state changes are visible on the next request
        state["m"] = M._replace(ready=False)
        clock["now"] = 500.0
        assert _get(server.port, "/readyz")[0] == 503
        assert _get(server.port, "/healthz")[0] == 503
    finally:
        server.stop()


def test_port_in_use_raises_oserror() -> None:
    first = HealthServer(lambda: M, port=0, liveness_timeout_s=120, host="127.0.0.1").start()
    try:
        with pytest.raises(OSError):
            HealthServer(lambda: M, port=first.port, liveness_timeout_s=120, host="127.0.0.1")
    finally:
        first.stop()
