"""Optional uplink to the SafeStream control plane, and ``safestream-control``.

With ``SAFESTREAM_CONTROL_URL`` and ``SAFESTREAM_CONTROL_TOKEN`` set, the
connector:

* **pulls** its signed policy, and the candidate to evaluate in shadow, from
  the control plane instead of a mounted file. The connector verifies every
  bundle itself, with the keys in ``SAFESTREAM_POLICY_PUBLIC_KEYS``, exactly
  as it verifies a file: the control plane distributes policies but is never
  trusted to have checked them, and cannot roll a connector back.
* **pushes** its audit events, byte for byte, so the control plane can anchor
  each hash chain's head outside the customer's own audit store. One event
  per audit window doubles as the connector's heartbeat.

What it never does:

* **send record content.** The only upload is an audit event: counts,
  entity-type names, versions and hashes (:func:`check_content_free` is the
  allow-list, and the control plane enforces the same one). Nothing else
  leaves the process.
* **accept connections.** Every request is outbound HTTPS from the connector;
  there is nothing for the control plane to connect to.
* **stop redaction.** It runs on its own thread. If the control plane is
  unreachable, slow or returns garbage, the connector keeps redacting under
  the last policy it verified, and audit events wait in a bounded queue.

Without those two settings none of this module runs: the connector makes no
network request beyond its Kafka brokers, exactly as before.

``safestream-control check`` tries a configuration from the command line:
token, reachability and whether the active bundle verifies with the
configured keys.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from typing import Any, NamedTuple

from safestream_enterprise import __version__, policy
from safestream_enterprise.connectors.health import ControlMetrics

logger = logging.getLogger("safestream_enterprise.control")

#: Largest response body read (a policy bundle of 1,000 rules is ~100 KiB).
MAX_RESPONSE_BYTES = 1024 * 1024
#: Audit events held while the control plane is unreachable. At one event a
#: minute this is over 16 hours; beyond it the oldest is dropped (and the
#: control plane then reports that chain as broken, which is the truth).
DEFAULT_QUEUE_MAX = 1000
#: Header naming the connector instance, so the control plane can place it in
#: a staged rollout. Same value as the audit events' ``instance``.
INSTANCE_HEADER = "x-safestream-instance"
#: Backoff bounds (seconds) after a failed request.
BACKOFF_MIN_S = 1.0
BACKOFF_MAX_S = 300.0


class ControlError(RuntimeError):
    """A request failed. The message names the route and status, never a token."""


class Response(NamedTuple):
    status: int
    headers: Mapping[str, str]
    body: bytes


#: ``(method, url, headers, body, timeout) -> Response``; raises ``OSError`` on
#: a network failure. Injected by tests; :func:`urllib_transport` otherwise.
Transport = Callable[[str, str, Mapping[str, str], "bytes | None", float], Response]


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: it would carry the token to another host."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def urllib_transport(ca_file: str | None = None) -> Transport:
    """HTTPS on the standard library. Honours ``HTTPS_PROXY``/``NO_PROXY``.

    ``ca_file`` adds trust for a corporate TLS-inspecting proxy; without it the
    system's CA bundle is used.
    """
    context = ssl.create_default_context(cafile=ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    opener = urllib.request.build_opener(
        _NoRedirects(), urllib.request.HTTPSHandler(context=context)
    )

    def transport(
        method: str, url: str, headers: Mapping[str, str], body: bytes | None, timeout: float
    ) -> Response:
        request = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with opener.open(request, timeout=timeout) as resp:
                return Response(resp.status, dict(resp.headers), resp.read(MAX_RESPONSE_BYTES + 1))
        except urllib.error.HTTPError as exc:  # 3xx/4xx/5xx: still an answer
            with exc:
                return Response(exc.code, dict(exc.headers), exc.read(MAX_RESPONSE_BYTES + 1))

    return transport


def validate_url(url: str) -> str:
    """The base URL, without a trailing slash. Raises ``ValueError``.

    HTTPS only, except to this machine (``http://localhost``, for tests
    against ``wrangler dev``): the token must never cross a network in clear.
    """
    parts = urllib.parse.urlsplit(url)
    loopback = parts.hostname in {"localhost", "127.0.0.1", "::1"}
    if parts.scheme != "https" and not (parts.scheme == "http" and loopback):
        raise ValueError("SAFESTREAM_CONTROL_URL must be an https:// URL")
    if not parts.hostname or parts.query or parts.fragment or parts.username:
        raise ValueError("SAFESTREAM_CONTROL_URL must be a plain base URL")
    return url.rstrip("/")


# ----------------------------------------------------------------------
# what may leave the process
# ----------------------------------------------------------------------

#: Strings an uplinked audit event may contain, by field. Mirrors
#: control-plane/src/validate.ts: names, versions, hashes and timestamps only.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
_ENTITY = re.compile(r"[a-z][a-z0-9_]{0,39}")
_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})")
_STRING_FIELDS: dict[str, re.Pattern[str]] = {
    "schema": re.compile(r"safestream\.audit/v2"),
    "connector_version": re.compile(r"[0-9A-Za-z.+-]{1,32}"),
    "instance": _NAME,
    "group_id": _NAME,
    "topics.ingress": _NAME,
    "topics.egress": _NAME,
    "topics.dlq": _NAME,
    "delivery": re.compile(r"at_least_once|exactly_once"),
    "redaction_mode": re.compile(r"replace|mask|pseudonymize"),
    "field_rules.fingerprint": _HASH,
    "policy.tenant": re.compile(r"[a-z0-9][a-z0-9-]{1,38}[a-z0-9]"),
    "policy.key_id": re.compile(r"[0-9a-f]{16}"),
    "shadow.candidate.tenant": re.compile(r"[a-z0-9][a-z0-9-]{1,38}[a-z0-9]"),
    "shadow.candidate.key_id": re.compile(r"[0-9a-f]{16}"),
    "shadow.since": _TIME,
    "chain.id": _NAME,
    "chain.prev": _HASH,
    "window.start": _TIME,
    "window.end": _TIME,
}
#: Objects whose *keys* are data (entity-type names), not field names.
_ENTITY_MAPS = {"redactions", "shadow.redactions.active", "shadow.redactions.candidate"}


def check_content_free(event: Any, path: str = "") -> None:
    """Raise ``ValueError`` unless ``event`` holds only counts, flags, nulls and
    allow-listed names, versions, hashes and timestamps.

    The connector runs this on every audit event before it is queued for the
    control plane, so a future field that could carry free text fails closed
    (the event stays local) instead of leaving the process.
    """
    if isinstance(event, dict):
        for key, value in event.items():
            if path in _ENTITY_MAPS:
                if not isinstance(key, str) or not _ENTITY.fullmatch(key):
                    raise ValueError(f"{path}: key is not an entity type")
                if type(value) is not int:
                    raise ValueError(f"{path}.{key}: must be a count")
                continue
            check_content_free(value, f"{path}.{key}" if path else str(key))
    elif isinstance(event, str):
        pattern = _STRING_FIELDS.get(path)
        if pattern is None or not pattern.fullmatch(event):
            raise ValueError(f"{path}: free text is not allowed in an uplinked event")
    elif isinstance(event, list):
        raise ValueError(f"{path}: lists are not allowed in an uplinked event")
    elif event is not None and not isinstance(event, (bool, int)):
        raise ValueError(f"{path}: only counts, flags and names are allowed")


# ----------------------------------------------------------------------
# client
# ----------------------------------------------------------------------


class ControlClient:
    """Talks to the control plane on behalf of one connector process.

    :meth:`refresh` and :meth:`deliver` do one round of work each and are what
    tests call; :meth:`start` runs them on a daemon thread. The connector
    reads :meth:`active_bundle` and :meth:`candidate_bundle` from its own
    thread and enqueues audit events with :meth:`enqueue`; nothing here ever
    blocks it.
    """

    def __init__(
        self,
        url: str,
        token: str,
        instance: str,
        transport: Transport | None = None,
        poll_s: float = 30.0,
        timeout_s: float = 10.0,
        queue_max: int = DEFAULT_QUEUE_MAX,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = validate_url(url)
        self._token = token
        self.instance = instance
        self._transport = transport or urllib_transport()
        self.poll_s = poll_s
        self.timeout_s = timeout_s
        self._clock = clock
        self._lock = threading.Lock()
        self._bundles: dict[str, bytes | None] = {"active": None, "candidate": None}
        self._etags: dict[str, str] = {}
        self._queue: deque[bytes] = deque(maxlen=queue_max)
        self._wake = threading.Event()
        self._stopping = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_ok: float | None = None
        self._backoff = 0.0
        #: Seconds of quiet before the next telemetry attempt after a failure.
        self._telemetry_retry_at = 0.0
        #: Goes up whenever a downloaded bundle changes, so the connector can
        #: check it at once instead of on its next reload tick.
        self.generation = 0
        self.requests_failed = 0
        self.telemetry_sent = 0
        self.telemetry_rejected = 0
        self.telemetry_dropped = 0

    # -- HTTP ----------------------------------------------------------

    def _request(
        self, method: str, route: str, body: bytes | None = None, etag: str | None = None
    ) -> Response:
        headers = {
            "authorization": f"Bearer {self._token}",
            "user-agent": f"safestream-enterprise/{__version__}",
            "accept": "application/json",
            INSTANCE_HEADER: self.instance,
        }
        if body is not None:
            headers["content-type"] = "application/json"
        if etag:
            headers["if-none-match"] = etag
        try:
            response = self._transport(method, self.url + route, headers, body, self.timeout_s)
        except (OSError, ValueError) as exc:  # URLError, timeouts, TLS failures, bad URL
            self._failed()
            raise ControlError(f"{method} {route}: {type(exc).__name__}") from None
        if len(response.body) > MAX_RESPONSE_BYTES:
            self._failed()
            raise ControlError(f"{method} {route}: response too large")
        if response.status >= 500 or response.status in (401, 403, 429):
            self._failed()
            raise ControlError(f"{method} {route}: HTTP {response.status}")
        with self._lock:
            self._last_ok = self._clock()
            self._backoff = 0.0
        return response

    def _failed(self) -> None:
        with self._lock:
            self.requests_failed += 1
            self._backoff = min(BACKOFF_MAX_S, max(BACKOFF_MIN_S, self._backoff * 2))

    def whoami(self) -> dict[str, Any]:
        """``{"tenant", "label", "id"}`` of the agent token. Raises :class:`ControlError`."""
        response = self._request("GET", "/v1/agent/whoami")
        if response.status != 200:
            raise ControlError(f"GET /v1/agent/whoami: HTTP {response.status}")
        try:
            data = json.loads(response.body)
            if not isinstance(data, dict) or not isinstance(data.get("tenant"), str):
                raise TypeError
        except (ValueError, TypeError):
            raise ControlError("GET /v1/agent/whoami: not a whoami response") from None
        return data

    # -- policies ------------------------------------------------------

    def _fetch(self, which: str) -> None:
        response = self._request("GET", f"/v1/agent/policy/{which}", etag=self._etags.get(which))
        if response.status == 304:
            return
        if response.status == 404:
            with self._lock:
                if self._bundles[which] is not None:
                    self.generation += 1
                self._bundles[which] = None
            self._etags.pop(which, None)
            return
        if response.status != 200:
            raise ControlError(f"GET /v1/agent/policy/{which}: HTTP {response.status}")
        with self._lock:
            if self._bundles[which] != response.body:
                self.generation += 1
            self._bundles[which] = response.body
        etag = {k.lower(): v for k, v in response.headers.items()}.get("etag")
        if etag:
            self._etags[which] = etag
        else:
            self._etags.pop(which, None)

    def refresh(self) -> None:
        """Download the active and candidate bundles if they changed.

        Raises :class:`ControlError`; what was downloaded before stays.
        """
        self._fetch("active")
        self._fetch("candidate")

    def active_bundle(self) -> bytes | None:
        """The active bundle as last downloaded (unverified), or ``None``."""
        with self._lock:
            return self._bundles["active"]

    def candidate_bundle(self) -> bytes | None:
        with self._lock:
            return self._bundles["candidate"]

    # -- telemetry -----------------------------------------------------

    def enqueue(self, event: bytes) -> None:
        """Queue one audit event (exactly the published bytes) for delivery.

        Never blocks or raises. A full queue drops its oldest event.
        """
        with self._lock:
            if len(self._queue) == self._queue.maxlen:
                self.telemetry_dropped += 1
            self._queue.append(event)
        self._wake.set()

    def deliver(self) -> int:
        """Send queued events in order until the queue is empty or a send fails.

        Returns the number sent. An event the control plane refuses for good
        (409: it does not extend the anchored chain; 422: not a content-free
        event) is dropped and counted: resending it would be refused forever.
        Anything else (network, 5xx, 401) leaves it at the head of the queue.
        """
        sent = 0
        while True:
            with self._lock:
                if not self._queue:
                    return sent
                event = self._queue[0]
            try:
                response = self._request("POST", "/v1/agent/telemetry", body=event)
            except ControlError as exc:
                logger.warning("audit event not delivered to the control plane (%s)", exc)
                return sent
            with self._lock:
                if self._queue and self._queue[0] is event:
                    self._queue.popleft()
            if response.status in (200, 202):
                self.telemetry_sent += 1
                sent += 1
            else:
                self.telemetry_rejected += 1
                logger.error(
                    "control plane refused an audit event (HTTP %d); dropped", response.status
                )

    def status(self) -> ControlMetrics:
        """Content-free view of the uplink, for /metrics."""
        with self._lock:
            connected = (
                self._last_ok is not None
                and self._clock() - self._last_ok <= 3 * self.poll_s + self.timeout_s
            )
            return ControlMetrics(
                connected=connected,
                requests_failed=self.requests_failed,
                telemetry_sent=self.telemetry_sent,
                telemetry_rejected=self.telemetry_rejected,
                telemetry_dropped=self.telemetry_dropped,
                queue_depth=len(self._queue),
            )

    # -- thread --------------------------------------------------------

    def _loop(self) -> None:
        next_refresh = 0.0
        while not self._stopping.is_set():
            now = self._clock()
            if now >= next_refresh:
                try:
                    self.refresh()
                except ControlError as exc:
                    logger.warning(
                        "control plane unreachable, keeping the policy in force (%s)", exc
                    )
                next_refresh = now + max(self.poll_s, self._backoff)
            if now >= self._telemetry_retry_at:
                before = self.requests_failed
                self.deliver()
                if self.requests_failed != before:
                    self._telemetry_retry_at = self._clock() + self._backoff
            with self._lock:
                pending = bool(self._queue)
            wait = next_refresh - self._clock()
            if pending:
                wait = min(wait, self._telemetry_retry_at - self._clock())
            self._wake.wait(max(0.05, wait))
            self._wake.clear()

    def start(self) -> ControlClient:
        self._thread = threading.Thread(target=self._loop, name="safestream-control", daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout_s: float) -> None:
        """Stop the thread, then try for up to ``timeout_s`` to deliver what is queued."""
        self._stopping.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout_s)
        deadline = self._clock() + timeout_s
        while self.status().queue_depth and self._clock() < deadline:
            if not self.deliver():
                break
        left = self.status().queue_depth
        if left:
            logger.warning("%d audit event(s) not delivered to the control plane at shutdown", left)


# ----------------------------------------------------------------------
# safestream-control
# ----------------------------------------------------------------------


def main(argv: Sequence[str] | None = None, transport: Transport | None = None) -> int:
    """Console entry point (``safestream-control``): 0 ok, 1 check failed, 2 usage."""
    parser = argparse.ArgumentParser(
        prog="safestream-control",
        description="Check a connector's control-plane settings (SAFESTREAM_CONTROL_*).",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser(
        "check",
        help="authenticate, download the active policy and verify it with the trusted keys",
    )
    parser.parse_args(argv)
    env = os.environ
    url, token = env.get("SAFESTREAM_CONTROL_URL", ""), env.get("SAFESTREAM_CONTROL_TOKEN", "")
    keys = env.get(policy.PUBLIC_KEYS_ENV, "")
    if not (url and token and keys):
        print(
            "safestream-control: set SAFESTREAM_CONTROL_URL, SAFESTREAM_CONTROL_TOKEN and "
            f"{policy.PUBLIC_KEYS_ENV}",
            file=sys.stderr,
        )
        return 2
    report: dict[str, Any] = {"url": url}
    try:
        client = ControlClient(
            url,
            token,
            env.get("HOSTNAME", "safestream-control-check"),
            transport or urllib_transport(env.get("SAFESTREAM_CONTROL_CA_FILE") or None),
        )
        who = client.whoami()
        report["tenant"], report["token"] = who["tenant"], who.get("label")
        wanted = env.get("SAFESTREAM_POLICY_TENANT")
        if wanted and wanted != who["tenant"]:
            raise ControlError(f"token is for tenant {who['tenant']}, not {wanted}")
        client.refresh()
        trusted = policy.parse_public_keys(keys)
        for which, data in (
            ("active", client.active_bundle()),
            ("candidate", client.candidate_bundle()),
        ):
            if data is None:
                report[which] = None
                continue
            verified = policy.verify(data, trusted, who["tenant"])
            report[which] = {"version": verified.version, "key_id": verified.key_id}
    except (ControlError, ValueError) as exc:  # PolicyError is a ValueError
        report["ok"] = False
        report["error"] = str(exc)
        print(json.dumps(report, indent=2))
        return 1
    report["ok"] = True
    if report["active"] is None:
        report["warning"] = (
            "no active policy yet: a connector without SAFESTREAM_POLICY_FILE will not "
            "start until one is promoted"
        )
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
