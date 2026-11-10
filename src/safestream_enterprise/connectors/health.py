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
from bisect import bisect_left
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import NamedTuple

#: Socket read timeout per connection, so a stalled client cannot pin a thread.
_REQUEST_TIMEOUT_S = 5.0


#: Upper bounds (seconds). A batch is up to SAFESTREAM_BATCH_SIZE records plus
#: the wait for broker acknowledgement; a record is one redaction.
BATCH_BUCKETS = (0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
RECORD_BUCKETS = (0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.05, 0.25)


class Histogram:
    """A fixed-bucket Prometheus histogram.

    Written by the main loop and read by the health thread without a lock: a
    scrape can be one observation behind, never corrupt.
    """

    def __init__(self, buckets: tuple[float, ...]) -> None:
        self.buckets = buckets
        self.counts = [0] * (len(buckets) + 1)  # last slot: above every bound (+Inf)
        self.sum = 0.0

    def observe(self, value: float) -> None:
        self.counts[bisect_left(self.buckets, value)] += 1
        self.sum += value

    def copy(self) -> Histogram:
        out = Histogram(self.buckets)
        out.counts, out.sum = self.counts[:], self.sum
        return out

    def render(self, name: str, help_text: str) -> list[str]:
        lines = [f"# HELP {name} {help_text}", f"# TYPE {name} histogram"]
        total = 0
        for bound, n in zip(self.buckets, self.counts, strict=False):
            total += n
            lines.append(f'{name}_bucket{{le="{bound:g}"}} {total}')
        total += self.counts[-1]
        lines += [
            f'{name}_bucket{{le="+Inf"}} {total}',
            f"{name}_sum {self.sum:.6f}",
            f"{name}_count {total}",
        ]
        return lines


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
    #: Records between this instance's position and the end of its partitions;
    #: ``None`` until it has a position on at least one.
    lag: int | None = None
    assigned_partitions: int = 0
    batch_seconds: Histogram | None = None
    record_seconds: Histogram | None = None


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
        "# HELP safestream_assigned_partitions Ingress partitions assigned to this instance.",
        "# TYPE safestream_assigned_partitions gauge",
        f"safestream_assigned_partitions {m.assigned_partitions}",
        "# HELP safestream_heartbeat_age_seconds Seconds since the main loop last advanced.",
        "# TYPE safestream_heartbeat_age_seconds gauge",
        f"safestream_heartbeat_age_seconds {max(0.0, now - m.heartbeat):.3f}",
        "# HELP safestream_ready 1 when the connector is consuming.",
        "# TYPE safestream_ready gauge",
        f"safestream_ready {int(m.ready)}",
    ]
    if m.lag is not None:
        lines += [
            "# HELP safestream_consumer_lag_records Records not yet consumed on this "
            "instance's partitions (as of its last fetch).",
            "# TYPE safestream_consumer_lag_records gauge",
            f"safestream_consumer_lag_records {m.lag}",
        ]
    if m.batch_seconds is not None:
        lines += m.batch_seconds.render(
            "safestream_batch_duration_seconds",
            "Time to redact, publish and commit one batch.",
        )
    if m.record_seconds is not None:
        lines += m.record_seconds.render(
            "safestream_record_duration_seconds",
            "Time to redact one record and hand it to the producer.",
        )
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
