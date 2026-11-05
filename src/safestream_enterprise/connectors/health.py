"""Liveness, readiness and Prometheus metrics for the Kafka connector.

A small HTTP server on a daemon thread, built on the standard library so the
image gains no dependency:

``GET /healthz``  liveness: 200 while the main loop's heartbeat is fresh.
                  A loop that stops iterating (a deadlock, a wedged native
                  call) goes stale and Kubernetes restarts the pod. A broker
                  outage does *not* fail it: the loop keeps polling, and a
                  restart could not fix the broker.
``GET /readyz``   readiness: 200 after the connector has subscribed, 503
                  before that and once shutdown has begun.
``GET /metrics``  Prometheus text format (version 0.0.4): counts only.

Like the OSS REST API this follows, the endpoint carries **no content**: only
counters and entity-type names, never record text, keys or headers. Request
lines are never logged. Each connection has a read timeout and anything but a
GET to a known path is refused.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

#: Socket read timeout per connection, so a stalled client cannot pin a thread.
_REQUEST_TIMEOUT_S = 5.0


class ConnectorMetrics(NamedTuple):
    """A point-in-time, content-free view of the connector."""

    ready: bool
    #: ``time.monotonic()`` of the last main-loop iteration or processed record.
    heartbeat: float
    egress_records: int
    dlq_records: int
    batches: int
    transaction_aborts: int
    #: Redactions per entity type (``"email" -> 12``).
    redactions: dict[str, int]
    audit_events: int = 0
    audit_failures: int = 0


def render_metrics(m: ConnectorMetrics, now: float) -> str:
    """Prometheus text exposition of ``m``."""
    lines = [
        "# HELP safestream_records_total Records published, by destination.",
        "# TYPE safestream_records_total counter",
        f'safestream_records_total{{destination="egress"}} {m.egress_records}',
        f'safestream_records_total{{destination="dlq"}} {m.dlq_records}',
        "# HELP safestream_redactions_total Redacted values, by entity type.",
        "# TYPE safestream_redactions_total counter",
    ]
    # Entity types come from the engine's own enum: safe label values.
    lines += [
        f'safestream_redactions_total{{entity_type="{t}"}} {n}'
        for t, n in sorted(m.redactions.items())
    ]
    lines += [
        "# HELP safestream_batches_total Batches committed.",
        "# TYPE safestream_batches_total counter",
        f"safestream_batches_total {m.batches}",
        "# HELP safestream_transaction_aborts_total Aborted transactions (exactly_once).",
        "# TYPE safestream_transaction_aborts_total counter",
        f"safestream_transaction_aborts_total {m.transaction_aborts}",
        "# HELP safestream_audit_events_total Compliance audit events delivered.",
        "# TYPE safestream_audit_events_total counter",
        f"safestream_audit_events_total {m.audit_events}",
        "# HELP safestream_audit_failures_total Audit events not delivered (window carried over).",
        "# TYPE safestream_audit_failures_total counter",
        f"safestream_audit_failures_total {m.audit_failures}",
        "# HELP safestream_heartbeat_age_seconds Seconds since the main loop last advanced.",
        "# TYPE safestream_heartbeat_age_seconds gauge",
        f"safestream_heartbeat_age_seconds {max(0.0, now - m.heartbeat):.3f}",
        "# HELP safestream_ready 1 when the connector is consuming.",
        "# TYPE safestream_ready gauge",
        f"safestream_ready {int(m.ready)}",
    ]
    return "\n".join(lines) + "\n"


def dispatch(
    method: str, path: str, m: ConnectorMetrics, now: float, liveness_timeout_s: float
) -> tuple[int, str, str]:
    """``(status, content type, body)`` for one request. Pure, so unit-testable."""
    route = path.split("?", 1)[0]
    if method != "GET":
        return 405, "text/plain", "method not allowed\n"
    if route == "/healthz":
        age = now - m.heartbeat
        if age <= liveness_timeout_s:
            return 200, "text/plain", "ok\n"
        return 503, "text/plain", f"main loop stalled for {age:.0f}s\n"
    if route == "/readyz":
        return (200, "text/plain", "ready\n") if m.ready else (503, "text/plain", "not ready\n")
    if route == "/metrics":
        return 200, "text/plain; version=0.0.4", render_metrics(m, now)
    return 404, "text/plain", "not found\n"


class HealthServer:
    """Serves :func:`dispatch` on ``host:port`` from a daemon thread.

    ``port=0`` binds an ephemeral port (tests); :attr:`port` reports the real one.
    """

    def __init__(
        self,
        snapshot: Callable[[], ConnectorMetrics],
        port: int,
        liveness_timeout_s: float,
        host: str = "0.0.0.0",  # kubelet probes and Prometheus reach the pod IP
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = _REQUEST_TIMEOUT_S

            def _serve(self, method: str) -> None:
                status, ctype, body = dispatch(
                    method, self.path, snapshot(), clock(), liveness_timeout_s
                )
                data = body.encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                # Request bodies are never read: close rather than reuse the socket.
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                self.close_connection = True

            def do_GET(self) -> None:
                self._serve("GET")

            def do_POST(self) -> None:
                self._serve("POST")

            def log_message(self, *args: object) -> None:
                pass  # never log request lines

        self._httpd = ThreadingHTTPServer((host, port), _Handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, name="safestream-health", daemon=True
        )

    @property
    def port(self) -> int:
        return int(self._httpd.server_address[1])

    def start(self) -> HealthServer:
        self._thread.start()
        return self

    def stop(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()
