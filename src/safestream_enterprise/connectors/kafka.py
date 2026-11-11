"""Kafka consume -> redact -> produce connector (sidecar or standalone consumer).

Data flow::

    ingress-logs ──consume──▶ StructuredRedactor ──produce──▶ egress-logs-clean
                                      │ (not JSON/XML / redaction raised / egress rejected)
                                      └────────produce──────▶ ingress-logs-dlq

Delivery semantics: **never unredacted to egress**, in one of two modes
(``SAFESTREAM_DELIVERY``):

``at_least_once`` (default)
* Auto-commit is off. Offsets are committed synchronously only after every
  message in a batch has been *acknowledged* by the egress brokers
  (``acks=all`` + idempotent producer). A crash between produce and commit
  replays the batch: duplicates are possible, loss is not.
* Any delivery failure raises :class:`DeliveryError` and the process exits
  non-zero *without* committing. The orchestrator restarts it and consumption
  resumes from the last committed offset. (Continuing in-process would move the
  in-memory position past the failed messages and a later commit would skip
  them for good.)

``exactly_once``
* Each batch is one Kafka transaction: its egress records, its DLQ records and
  the consumer offsets commit atomically (``send_offsets_to_transaction``), so
  a crash at any point either publishes the whole batch with its offsets or
  none of it. Consumers of the egress topic must read with
  ``isolation.level=read_committed`` to get the guarantee.
* An abortable transaction error aborts and retries the same batch in-process
  (up to :data:`MAX_TRANSACTION_ATTEMPTS`); nothing was visible to
  read_committed consumers, so the retry cannot duplicate. If every attempt
  fails, :class:`DeliveryError` exits the process without committing, as above.
* Zombie instances are fenced by the consumer-group generation (KIP-447), so
  the ``transactional.id`` only has to be unique among live instances; it
  defaults to ``<group id>-<hostname>`` (the pod name on Kubernetes).

Both modes:
* A message that cannot be processed (neither JSON nor XML, redaction raised, or the
  producer refused the redacted record) is never forwarded to egress and never
  stops the loop. It is routed, raw, to the dead-letter topic with the
  exception class in the ``x-safestream-error`` header; its offset is committed
  with the batch once the DLQ acknowledges it. The DLQ must carry the same ACLs
  and retention as the ingress topic: it holds unredacted data by design.

Configuration is entirely environment-driven (12-factor) so the same image runs
as a Kubernetes Deployment or a sidecar. It is validated by pydantic at startup,
so a bad value fails the pod immediately instead of the first batch; secrets
are held as ``SecretStr`` and never appear in logs, reprs or validation errors.
Any librdkafka property can be passed as ``SAFESTREAM_KAFKA_<PROPERTY>`` with
dots written as underscores, e.g.
``SAFESTREAM_KAFKA_SECURITY_PROTOCOL=SASL_SSL`` -> ``security.protocol``.

Logging never includes payloads, keys or header values: only topic,
partition, offset and counts.
"""

from __future__ import annotations

import copy
import logging
import os
import signal
import socket
import sys
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from pathlib import Path
from types import FrameType
from typing import Literal

import orjson
from confluent_kafka import (
    TIMESTAMP_NOT_AVAILABLE,
    Consumer,
    KafkaError,
    KafkaException,
    Message,
    Producer,
    TopicPartition,
)
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator
from safestream_redactor import RedactionMode, RedactionStats

from safestream_enterprise import __version__
from safestream_enterprise.connectors.health import (
    BATCH_BUCKETS,
    RECORD_BUCKETS,
    ConnectorMetrics,
    HealthServer,
    Histogram,
)
from safestream_enterprise.logs import configure_logging
from safestream_enterprise.parsers.json_ast import StructuredRedactor
from safestream_enterprise.rules import make_redactor

logger = logging.getLogger("safestream_enterprise.kafka")

#: Prefix for pass-through librdkafka settings (see module docstring).
KAFKA_ENV_PREFIX = "SAFESTREAM_KAFKA_"
#: Header naming which path redacted the record: ``structural`` or ``text``.
MODE_HEADER = "x-safestream-redaction"
#: DLQ header carrying the exception *class* (never its message: it may quote data).
ERROR_HEADER = "x-safestream-error"
#: exactly_once: transaction attempts per batch before giving up (and restarting).
MAX_TRANSACTION_ATTEMPTS = 5
#: librdkafka properties the delivery guarantees depend on; SAFESTREAM_KAFKA_*
#: may not override them (a stray ENABLE_AUTO_COMMIT=true would silently commit
#: offsets before egress is acknowledged).
PROTECTED_CLIENT_PROPERTIES = frozenset(
    {
        "bootstrap.servers",
        "group.id",
        "enable.auto.commit",
        "enable.auto.offset.store",
        "auto.offset.reset",
        "isolation.level",
        "enable.idempotence",
        "acks",
        "transactional.id",
    }
)
#: Broker verdicts on one record that no retry or restart can change: the
#: redacted record is too large for the egress topic, or its (preserved) event
#: time is outside what the topic accepts. Such a record goes to the DLQ;
#: replaying it would fail the same way forever.
PERMANENT_RECORD_ERRORS = frozenset(
    {KafkaError.MSG_SIZE_TOO_LARGE, KafkaError.INVALID_RECORD, KafkaError.INVALID_TIMESTAMP}
)
#: Schema identifier carried by every audit event; bump on incompatible change.
AUDIT_SCHEMA = "safestream.audit/v1"


class DeliveryError(RuntimeError):
    """One or more produced records were not acknowledged; offsets not committed."""


class ConnectorConfig(BaseModel):
    """Validated runtime settings, normally built by :meth:`from_env`.

    Immutable once built (``frozen``) and closed to unknown fields
    (``extra="forbid"``), so a typo in code fails loudly instead of being
    silently ignored.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    bootstrap_servers: str = Field(min_length=1)
    group_id: str = Field(default="safestream-redactor", min_length=1)
    ingress_topic: str = Field(default="ingress-logs", min_length=1)
    egress_topic: str = Field(default="egress-logs-clean", min_length=1)
    dlq_topic: str = Field(default="ingress-logs-dlq", min_length=1)
    #: Records per consume/commit cycle.
    batch_size: int = Field(default=500, ge=1, le=100_000)
    poll_timeout_s: float = Field(default=1.0, gt=0)
    #: How long to wait for egress acknowledgements before failing the batch.
    flush_timeout_s: float = Field(default=30.0, gt=0)
    #: OSS redaction mode applied to every hit.
    redaction_mode: RedactionMode = RedactionMode.REPLACE
    #: Key for ``pseudonymize`` (consistent tokens across topics and days).
    hmac_key: SecretStr | None = None
    #: What happens to a payload that is neither valid JSON nor valid XML.
    #: ``dlq``: it goes to the DLQ untouched. ``redact_text``: it is redacted as
    #: free text and sent to egress instead.
    unparseable: Literal["dlq", "redact_text"] = "dlq"
    #: ``at_least_once``: commit offsets after egress acks (duplicates possible
    #: after a crash). ``exactly_once``: one Kafka transaction per batch.
    delivery: Literal["at_least_once", "exactly_once"] = "at_least_once"
    #: exactly_once only. Defaults to ``<group_id>-<hostname>``.
    transactional_id: str | None = Field(default=None, min_length=1)
    #: JSON file of customer field rules (see :mod:`safestream_enterprise.rules`),
    #: typically a mounted ConfigMap. ``None`` uses the built-in rules only.
    field_rules_file: Path | None = None
    #: Port for /healthz, /readyz and /metrics (see :mod:`.health`); 0 disables.
    metrics_port: int = Field(default=9400, ge=0, le=65535)
    #: /healthz fails once the main loop has not advanced for this long.
    liveness_timeout_s: float = Field(default=120.0, gt=0)
    #: Topic for compliance audit events (see :meth:`KafkaRedactionConnector.audit_event`);
    #: ``None`` disables auditing.
    audit_topic: str | None = Field(default=None, min_length=1)
    #: Seconds per audit window.
    audit_interval_s: float = Field(default=60.0, ge=1)
    #: Extra librdkafka properties applied to both consumer and producer
    #: (security.protocol, sasl.*, ssl.* ...). Secret-wrapped: may hold passwords.
    client_overrides: dict[str, SecretStr] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> ConnectorConfig:
        # A topic collision is a data-safety bug, not a style issue: egress ==
        # ingress loops forever, and dlq == egress publishes raw records to the
        # clean topic.
        topics: tuple[str, ...] = (self.ingress_topic, self.egress_topic, self.dlq_topic)
        topics += (self.audit_topic,) if self.audit_topic else ()
        if len(set(topics)) != len(topics):
            raise ValueError("ingress, egress, DLQ and audit topics must all be different")
        if self.redaction_mode is RedactionMode.PSEUDONYMIZE and not self.hmac_key:
            raise ValueError("pseudonymize mode requires SAFESTREAM_HMAC_KEY")
        protected = sorted(PROTECTED_CLIENT_PROPERTIES & set(self.client_overrides))
        if protected:
            # Names only: the values may be secrets.
            raise ValueError(
                f"SAFESTREAM_KAFKA_* may not set {protected}: the delivery guarantees "
                "depend on them; use the dedicated SAFESTREAM_*/KAFKA_* settings instead"
            )
        if self.transactional_id and self.delivery != "exactly_once":
            raise ValueError(
                "SAFESTREAM_TRANSACTIONAL_ID requires SAFESTREAM_DELIVERY=exactly_once"
            )
        # The heartbeat can legitimately pause for one flush/commit wait; a
        # liveness window shorter than that would restart healthy pods.
        if self.liveness_timeout_s < 2 * self.flush_timeout_s:
            raise ValueError(
                "SAFESTREAM_LIVENESS_TIMEOUT_S must be at least twice SAFESTREAM_FLUSH_TIMEOUT_S"
            )
        return self

    @property
    def exactly_once(self) -> bool:
        return self.delivery == "exactly_once"

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ConnectorConfig:
        """Build and validate config from environment variables.

        Raises :class:`pydantic.ValidationError` (a ``ValueError``) on any bad
        or missing value. Unset variables take the field defaults.
        """
        env = os.environ if env is None else env
        names = {
            "KAFKA_BOOTSTRAP_SERVERS": "bootstrap_servers",
            "KAFKA_GROUP_ID": "group_id",
            "INGRESS_TOPIC": "ingress_topic",
            "EGRESS_TOPIC": "egress_topic",
            "DLQ_TOPIC": "dlq_topic",
            "SAFESTREAM_BATCH_SIZE": "batch_size",
            "SAFESTREAM_FLUSH_TIMEOUT_S": "flush_timeout_s",
            "SAFESTREAM_MODE": "redaction_mode",
            "SAFESTREAM_HMAC_KEY": "hmac_key",
            "SAFESTREAM_UNPARSEABLE": "unparseable",
            "SAFESTREAM_DELIVERY": "delivery",
            "SAFESTREAM_TRANSACTIONAL_ID": "transactional_id",
            "SAFESTREAM_FIELD_RULES_FILE": "field_rules_file",
            "SAFESTREAM_METRICS_PORT": "metrics_port",
            "SAFESTREAM_LIVENESS_TIMEOUT_S": "liveness_timeout_s",
            "SAFESTREAM_AUDIT_TOPIC": "audit_topic",
            "SAFESTREAM_AUDIT_INTERVAL_S": "audit_interval_s",
        }
        data: dict[str, object] = {field: env[var] for var, field in names.items() if env.get(var)}
        data["client_overrides"] = {
            name[len(KAFKA_ENV_PREFIX) :].lower().replace("_", "."): value
            for name, value in env.items()
            if name.startswith(KAFKA_ENV_PREFIX)
        }
        return cls.model_validate(data)

    def _overrides(self) -> dict[str, str]:
        return {k: v.get_secret_value() for k, v in self.client_overrides.items()}

    def consumer_config(self) -> dict[str, str | int | bool]:
        return {
            "bootstrap.servers": self.bootstrap_servers,
            "group.id": self.group_id,
            # We commit manually, after egress acknowledges the batch.
            "enable.auto.commit": False,
            # A brand-new group must redact the backlog, not skip it.
            "auto.offset.reset": "earliest",
            # Never redact (and re-publish) records from aborted transactions.
            "isolation.level": "read_committed",
            # Cooperative rebalancing: scaling the Deployment doesn't stop the world.
            "partition.assignment.strategy": "cooperative-sticky",
            **self._overrides(),
        }

    def producer_config(self) -> dict[str, str | int | bool]:
        config: dict[str, str | int | bool] = {
            "bootstrap.servers": self.bootstrap_servers,
            # Idempotence implies acks=all, unbounded retries, ordered delivery
            # per partition: no duplicates or reordering from producer retries.
            "enable.idempotence": True,
            "acks": "all",
            "compression.type": "zstd",
            "linger.ms": 20,
        }
        if self.exactly_once:
            config["transactional.id"] = (
                self.transactional_id or f"{self.group_id}-{socket.gethostname()}"
            )
        return {**config, **self._overrides()}


class KafkaRedactionConnector:
    """Consume ingress, redact each record, publish to egress, commit offsets.

    ``consumer`` and ``producer`` are injected so tests (and embedding
    applications) can supply their own; :func:`main` builds real ones.
    """

    def __init__(
        self,
        config: ConnectorConfig,
        redactor: StructuredRedactor,
        consumer: Consumer,
        producer: Producer,
    ) -> None:
        self.config = config
        self.redactor = redactor
        self.consumer = consumer
        self.producer = producer
        self.stats = RedactionStats()
        # Content-free counters for /metrics (read from the health thread;
        # plain int/attribute reads are atomic under the GIL).
        self.egress_records = 0
        self.dead_lettered = 0
        self.batches = 0
        self.transaction_aborts = 0
        self.audit_events = 0
        self.audit_failures = 0
        self.lag: int | None = None
        self.assigned_partitions = 0
        self.batch_seconds = Histogram(BATCH_BUCKETS)
        self.record_seconds = Histogram(RECORD_BUCKETS)
        self.ready = False
        self.heartbeat = time.monotonic()
        self._running = True
        # Failed deliveries with the ingress record they came from (None for a
        # DLQ record: a failed dead-letter has nowhere further to go).
        self._delivery_errors: list[tuple[KafkaError, Message | None]] = []
        # exactly_once: ingress positions whose egress record the broker
        # rejected for good, with the error name; the retry dead-letters them.
        self._rejected: dict[tuple[str | None, int | None, int | None], str] = {}
        # Audit window: counters are reported as deltas against the snapshot
        # taken when the previous audit event was *acknowledged*, so a failed
        # send is carried into the next window instead of being lost.
        self.instance = socket.gethostname()  # the pod name on Kubernetes
        # Counters as of the last *committed* batch. Audits report from this, so
        # records of a batch that failed (and will be replayed after a restart)
        # are never reported, and replays are never counted twice.
        self._committed = self.snapshot()
        self._audit_base = self._committed
        self._audit_window_start = datetime.now(timezone.utc)
        self._audit_due = time.monotonic() + config.audit_interval_s

    def snapshot(self) -> ConnectorMetrics:
        """A content-free view for the health/metrics endpoint."""
        return ConnectorMetrics(
            ready=self.ready,
            heartbeat=self.heartbeat,
            egress_records=self.egress_records,
            dlq_records=self.dead_lettered,
            batches=self.batches,
            transaction_aborts=self.transaction_aborts,
            audit_events=self.audit_events,
            audit_failures=self.audit_failures,
            redactions=dict(self.stats.counts),
            lag=self.lag,
            assigned_partitions=self.assigned_partitions,
            batch_seconds=self.batch_seconds.copy(),
            record_seconds=self.record_seconds.copy(),
        )

    def _update_lag(self) -> None:
        """Refresh lag from librdkafka's local state (no broker round trip).

        Counts partitions this instance has a position on. Lag on partitions
        nobody is consuming is only visible to a Kafka-side exporter.
        """
        try:
            positions = self.consumer.position(self.consumer.assignment())
            lag: int | None = None
            for tp in positions:
                if tp.offset < 0:
                    continue  # nothing fetched from this partition yet
                _low, high = self.consumer.get_watermark_offsets(tp, cached=True)
                if high >= 0:
                    lag = (lag or 0) + max(0, high - tp.offset)
            self.lag, self.assigned_partitions = lag, len(positions)
        except KafkaException:
            pass  # e.g. mid-rebalance: keep the last value

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def stop(self, signum: int | None = None, _frame: FrameType | None = None) -> None:
        """Request a graceful stop; the current batch finishes and is committed."""
        logger.info("stop requested (signal=%s); draining current batch", signum)
        self._running = False

    def run(self) -> None:
        """Main loop. Returns after :meth:`stop`; raises on unrecoverable errors."""
        if self.config.exactly_once:
            # Registers the transactional.id and aborts any transaction a
            # previous instance with the same id left open.
            self.producer.init_transactions(self.config.flush_timeout_s)
        self.consumer.subscribe([self.config.ingress_topic])
        self.ready = True
        logger.info(
            "consuming %s -> %s (group=%s, delivery=%s)",
            self.config.ingress_topic,
            self.config.egress_topic,
            self.config.group_id,
            self.config.delivery,
        )
        try:
            while self._running:
                self.heartbeat = time.monotonic()
                batch = self.consumer.consume(
                    num_messages=self.config.batch_size, timeout=self.config.poll_timeout_s
                )
                if batch:
                    self.process_batch(batch)
                self._update_lag()
                self._maybe_audit()
        finally:
            self.ready = False
            try:
                # Close the last window so no counts go unreported on shutdown.
                self._maybe_audit(final=True)
            except Exception as exc:  # never mask the exception that ended the loop
                logger.error("final audit event not delivered (%s)", type(exc).__name__)
            # Order matters: flush in-flight egress first, then close the consumer
            # (which leaves the group so partitions rebalance immediately).
            self.producer.flush(self.config.flush_timeout_s)
            self.consumer.close()
            logger.info("stopped: %s; dead-lettered=%d", self.stats.summary(), self.dead_lettered)

    # ------------------------------------------------------------------
    # compliance audit events
    # ------------------------------------------------------------------

    def audit_event(
        self,
        base: ConnectorMetrics,
        current: ConnectorMetrics,
        start: datetime,
        end: datetime,
        final: bool,
    ) -> dict[str, object]:
        """One content-free audit event covering ``start``..``end``.

        Counts only, plus the configuration an auditor needs to interpret them:
        which delivery and redaction modes ran, and a fingerprint of the exact
        field-rule table in force (the rules themselves are not included).
        """
        redactions = {
            entity: n - base.redactions.get(entity, 0)
            for entity, n in sorted(current.redactions.items())
            if n - base.redactions.get(entity, 0) > 0
        }
        return {
            "schema": AUDIT_SCHEMA,
            "connector_version": __version__,
            "instance": self.instance,
            "group_id": self.config.group_id,
            "topics": {
                "ingress": self.config.ingress_topic,
                "egress": self.config.egress_topic,
                "dlq": self.config.dlq_topic,
            },
            "delivery": self.config.delivery,
            "redaction_mode": self.config.redaction_mode.value,
            "field_rules": {
                "count": getattr(self.redactor, "rule_count", None),
                "fingerprint": getattr(self.redactor, "rules_fingerprint", None),
            },
            "window": {
                "start": start.isoformat(timespec="milliseconds"),
                "end": end.isoformat(timespec="milliseconds"),
                "final": final,
            },
            "records": {
                "egress": current.egress_records - base.egress_records,
                "dlq": current.dlq_records - base.dlq_records,
            },
            "redactions": redactions,
            "batches": current.batches - base.batches,
            "transaction_aborts": current.transaction_aborts - base.transaction_aborts,
        }

    def _maybe_audit(self, final: bool = False) -> None:
        """Publish the audit event for the current window if it is due.

        Runs on the main loop between batches, so it never interleaves with a
        batch's transaction. Every window is reported, including empty ones:
        "nothing processed" is evidence too.
        """
        if not self.config.audit_topic:
            return
        now = time.monotonic()
        if not final and now < self._audit_due:
            return
        self._audit_due = now + self.config.audit_interval_s
        current = self._committed
        end = datetime.now(timezone.utc)
        event = self.audit_event(self._audit_base, current, self._audit_window_start, end, final)
        if self._publish_audit(orjson.dumps(event)):
            self._audit_base, self._audit_window_start = current, end
            self.audit_events += 1
        else:
            self.audit_failures += 1

    def _publish_audit(self, data: bytes) -> bool:
        """Deliver one audit event; ``False`` (logged) if it was not acknowledged.

        A lost audit event never stops redaction: the window simply stays open
        and the next event covers it. Only a fatal producer error (e.g. fenced
        by a newer instance) propagates, as it would from a batch.
        """
        assert self.config.audit_topic is not None
        errors: list[KafkaError] = []

        def on_delivery(err: KafkaError | None, _msg: Message) -> None:
            if err is not None:
                errors.append(err)

        key = self.instance.encode()
        try:
            if self.config.exactly_once:
                # A transactional producer can only write inside a transaction.
                self.producer.begin_transaction()
                try:
                    self.producer.produce(
                        self.config.audit_topic, value=data, key=key, on_delivery=on_delivery
                    )
                    self._commit_transaction()
                except KafkaException as exc:
                    if exc.args[0].txn_requires_abort():
                        self.producer.abort_transaction(self.config.flush_timeout_s)
                    raise
            else:
                self.producer.produce(
                    self.config.audit_topic, value=data, key=key, on_delivery=on_delivery
                )
                if self.producer.flush(self.config.flush_timeout_s) or errors:
                    raise DeliveryError(f"audit event not acknowledged: {errors[:1]}")
        except KafkaException as exc:
            if exc.args[0].fatal():
                raise
            logger.error("audit event not delivered (%s); window carried over", exc.args[0])
            return False
        except (DeliveryError, BufferError) as exc:
            logger.error("audit event not delivered (%s); window carried over", exc)
            return False
        return True

    # ------------------------------------------------------------------
    # batch processing
    # ------------------------------------------------------------------

    def _produce(
        self,
        topic: str,
        value: bytes | None,
        key: str | bytes | None,
        headers: list[tuple[str, str | bytes | None]],
        timestamp: int,
        source: Message | None = None,
    ) -> None:
        """Produce one record, applying backpressure when the local queue is full.

        ``source`` is the ingress record an egress record was made from, so a
        broker rejection can be traced back to it and dead-lettered.
        """

        def on_delivery(err: KafkaError | None, _msg: Message) -> None:
            # Runs inside producer.poll()/flush() on this thread: no lock needed.
            if err is not None:
                self._delivery_errors.append((err, source))

        while True:
            try:
                self.producer.produce(
                    topic,
                    value=value,
                    key=key,
                    headers=headers,
                    timestamp=timestamp,
                    on_delivery=on_delivery,
                )
                return
            except BufferError:
                # librdkafka's queue is full: serve delivery reports to drain it.
                self.producer.poll(1.0)

    def _redact_bytes(self, data: str | bytes) -> str | bytes:
        """Redact a key or header value; return it *unchanged* if nothing was found.

        Re-serialising would rewrite values with nothing sensitive in them
        (``1e3`` -> ``1000.0``, ``{"id": 7}`` -> ``{"id":7}``, large numeric IDs
        losing precision), which would move records to other partitions and
        corrupt business keys. Redactions that do happen are counted, so they
        appear in metrics and audit events.
        """
        found = RedactionStats()
        redacted = self.redactor.redact_line(data, found).data
        if not found.total:
            return data
        self.stats.counts.update(found.counts)
        return redacted

    def handle_message(self, msg: Message) -> None:
        """Redact one record and hand it to the producer (not yet acknowledged)."""
        rejected = self._rejected.get(_position(msg))
        if rejected:
            # exactly_once retry: the broker refused this record's redacted form.
            self._dead_letter(msg, rejected)
            return
        value, key, raw_headers, timestamp = _parts(msg)
        try:
            if value is None:
                # Tombstone: nothing to redact, but compacted topics need it forwarded.
                out_value: bytes | None = None
                mode = b"tombstone"
            else:
                # JSON and XML are both handled structurally. strict: anything
                # else raises StructuredParseError -> DLQ.
                record = self.redactor.redact_line(
                    value, self.stats, strict=self.config.unparseable == "dlq"
                )
                out_value = record.data
                mode = b"structural" if record.structured else b"text"
            # Keys and header values can carry PII too (user-id partition keys,
            # forwarded auth headers). Values without findings come back unchanged,
            # so ordinary keys still hash to the same partition.
            out_key = self._redact_bytes(key) if key is not None else None
            out_headers: list[tuple[str, str | bytes | None]] = [
                (name, self._redact_bytes(hv) if hv else hv) for name, hv in raw_headers
            ]
            out_headers.append((MODE_HEADER, mode))
            # Inside the try: a synchronous produce rejection (e.g. the redacted
            # record exceeds message.max.bytes) would otherwise crash-loop on
            # this one record forever.
            self._produce(
                self.config.egress_topic, out_value, out_key, out_headers, timestamp, source=msg
            )
            self.egress_records += 1
        except Exception as exc:  # any per-record failure: DLQ, never egress
            # Class name only: exception messages can quote record content.
            self._dead_letter(msg, type(exc).__name__)

    def _dead_letter(self, msg: Message, reason: str) -> None:
        """Route the *original* record to the DLQ, tagged with ``reason``.

        ``reason`` is an exception class or Kafka error name, never free text
        that could quote record content.
        """
        logger.error(
            "dead-lettering %s[%s]@%s (%s)", msg.topic(), msg.partition(), msg.offset(), reason
        )
        value, key, headers, timestamp = _parts(msg)
        self.dead_lettered += 1
        self._produce(
            self.config.dlq_topic,
            value,
            key,
            [*headers, (ERROR_HEADER, reason.encode())],
            timestamp,
        )

    def _take_rejected(self) -> tuple[list[tuple[KafkaError, Message]], list[KafkaError]]:
        """Drain delivery errors into (records the broker rejected for good, the rest)."""
        failures, self._delivery_errors = self._delivery_errors, []
        rejected = [
            (err, src)
            for err, src in failures
            if src is not None and err.code() in PERMANENT_RECORD_ERRORS
        ]
        other = [
            err for err, src in failures if src is None or err.code() not in PERMANENT_RECORD_ERRORS
        ]
        return rejected, other

    def process_batch(self, batch: list[Message]) -> None:
        """Redact and publish a batch, then commit its offsets (all or nothing)."""
        messages: list[Message] = []
        for msg in batch:
            err = msg.error()
            if err is None:
                messages.append(msg)
            elif err.fatal():
                raise KafkaException(err)
            else:
                # Transient broker/partition errors: librdkafka retries itself.
                logger.warning("consumer error: %s", err)
        if not messages:
            return  # only error events: no new offsets to commit
        started = time.perf_counter()
        if self.config.exactly_once:
            self._process_transactional(messages)
        else:
            self._process_at_least_once(messages)
        self.batch_seconds.observe(time.perf_counter() - started)

    def _publish(self, messages: list[Message]) -> None:
        for msg in messages:
            started = time.perf_counter()
            self.handle_message(msg)
            self.record_seconds.observe(time.perf_counter() - started)
            # Serve delivery callbacks so the local queue keeps draining.
            self.producer.poll(0)
            # A large batch is progress, not a stall: keep liveness fresh.
            self.heartbeat = time.monotonic()

    def _process_at_least_once(self, messages: list[Message]) -> None:
        self._publish(messages)
        remaining = self.producer.flush(self.config.flush_timeout_s)
        rejected, other = self._take_rejected()
        if rejected and not remaining and not other:
            # The broker refused these records and will refuse them again after
            # a restart, so a replay would loop forever. Everything else in the
            # batch was acknowledged: dead-letter the originals and carry on.
            for err, src in rejected:
                self.egress_records -= 1
                self._dead_letter(src, err.name())
            remaining = self.producer.flush(self.config.flush_timeout_s)
            rejected, other = self._take_rejected()
        if remaining or rejected or other:
            errors = [str(e) for e in [*other, *(e for e, _ in rejected)][:5]]
            raise DeliveryError(
                f"{remaining} record(s) unflushed, delivery errors: {errors}; "
                "offsets NOT committed, batch will be replayed after restart"
            )
        # Synchronous: when this returns, a restart resumes after this batch.
        self.consumer.commit(asynchronous=False)
        self.batches += 1
        self._committed = self.snapshot()

    def _process_transactional(self, messages: list[Message]) -> None:
        """Publish ``messages`` and commit their offsets in one transaction.

        Abortable failures abort and retry the same in-memory batch: the
        consumer position is never rewound because offsets are committed
        explicitly from ``messages``, not from the consumer's position.
        """
        offsets = _next_offsets(messages)
        for attempt in range(1, MAX_TRANSACTION_ATTEMPTS + 1):
            # Counters are restored on abort so a retried batch isn't counted twice.
            saved = (copy.deepcopy(self.stats), self.dead_lettered, self.egress_records)
            self.producer.begin_transaction()
            try:
                self._publish(messages)
                self.producer.send_offsets_to_transaction(
                    offsets, self.consumer.consumer_group_metadata(), self.config.flush_timeout_s
                )
                self._commit_transaction()
            except KafkaException as exc:
                error: KafkaError = exc.args[0]
                if not error.txn_requires_abort():
                    raise  # fatal (e.g. fenced by a newer instance): exit for restart
                logger.warning(
                    "transaction aborted (attempt %d/%d): %s",
                    attempt,
                    MAX_TRANSACTION_ATTEMPTS,
                    error.name(),
                )
                self.producer.abort_transaction(self.config.flush_timeout_s)
                # A record the broker rejected for good would abort every retry
                # too: remember it, and the next attempt dead-letters it instead.
                self.producer.poll(0)  # serve any delivery reports still queued
                rejected, _ = self._take_rejected()
                self._rejected.update({_position(src): err.name() for err, src in rejected})
                self.stats, self.dead_lettered, self.egress_records = saved
                self.transaction_aborts += 1
                continue
            self._delivery_errors.clear()
            self._rejected.clear()
            self.batches += 1
            self._committed = self.snapshot()
            return
        raise DeliveryError(
            f"transaction aborted {MAX_TRANSACTION_ATTEMPTS} times; offsets NOT committed, "
            "batch will be replayed after restart"
        )

    def _commit_transaction(self) -> None:
        """Commit, retrying errors librdkafka marks retriable (e.g. a timeout)."""
        for attempt in range(1, MAX_TRANSACTION_ATTEMPTS + 1):
            # Each attempt can wait a full flush timeout; a retry is progress,
            # so keep liveness fresh rather than let kubelet kill a recovering pod.
            self.heartbeat = time.monotonic()
            try:
                self.producer.commit_transaction(self.config.flush_timeout_s)
                return
            except KafkaException as exc:
                if not exc.args[0].retriable() or attempt == MAX_TRANSACTION_ATTEMPTS:
                    raise


def _position(msg: Message) -> tuple[str | None, int | None, int | None]:
    return msg.topic(), msg.partition(), msg.offset()


def _parts(
    msg: Message,
) -> tuple[bytes | None, str | bytes | None, list[tuple[str, str | bytes | None]], int]:
    """``(value, key, headers, timestamp)`` of a consumed record."""
    ts_type, ts = msg.timestamp()
    # Preserve event time so downstream windowing/retention is unaffected.
    timestamp = ts if ts_type != TIMESTAMP_NOT_AVAILABLE else 0
    headers = msg.headers() or []
    # Consumed messages carry a list; the stubs also allow a dict.
    raw_headers = list(headers.items()) if isinstance(headers, dict) else headers
    return msg.value(), msg.key(), raw_headers, timestamp


def _next_offsets(messages: list[Message]) -> list[TopicPartition]:
    """The offsets to commit for ``messages``: last offset + 1 per partition."""
    last: dict[tuple[str, int], int] = {}
    for msg in messages:
        topic, partition, offset = msg.topic(), msg.partition(), msg.offset()
        # Always set on consumed (non-error) messages; the stubs type them Optional.
        if topic is None or partition is None or offset is None:
            raise KafkaException(KafkaError(KafkaError._BAD_MSG, "message without position"))
        key = (topic, partition)
        last[key] = max(last.get(key, -1), offset)
    return [TopicPartition(topic, part, off + 1) for (topic, part), off in last.items()]


def build_redactor(config: ConnectorConfig) -> StructuredRedactor:
    """The structured redactor for ``config``, built by :func:`.rules.make_redactor`.

    ``hmac_key`` keys pseudonymize mode so the same customer maps to the same
    token across every topic and day. Mount it from a Secret; never bake it
    into the image.

    ``field_rules_file`` adds customer field rules. It is read once, here: a
    changed ConfigMap takes effect on the next rollout, so every replica runs
    the same rules. Raises ``ValueError`` (``FieldRulesError``) on a bad file.
    """
    key = config.hmac_key.get_secret_value().encode() if config.hmac_key else None
    redactor = make_redactor(config.redaction_mode, key, config.field_rules_file)
    if config.field_rules_file:
        # Rule count only: a log line must never echo customer schema details
        # that could be sensitive themselves.
        logger.info("loaded %d field rules from %s", redactor.rule_count, config.field_rules_file)
    return redactor


#: Exit code when the watchdog ends a stalled process.
EXIT_STALLED = 3


def watchdog(
    connector: KafkaRedactionConnector,
    timeout_s: float,
    interval_s: float = 5.0,
    exit_process: Callable[[int], None] = os._exit,
) -> None:
    """Exit the process once the main loop has not advanced for ``timeout_s``.

    A Kafka client call can block far past its own timeout (seen in
    ``send_offsets_to_transaction`` after a broker crash). Nothing in-process
    can interrupt it, so the only recovery is a restart, and exiting is safe:
    offsets are uncommitted and an open transaction is aborted by the next
    instance. ``/healthz`` reports the same condition to Kubernetes; this makes
    it hold where nothing is probing (``docker run``, the metrics port turned off).
    """
    while True:
        time.sleep(interval_s)
        age = time.monotonic() - connector.heartbeat
        if age > timeout_s:
            logger.critical(
                "main loop stalled for %.0fs (a Kafka client call did not return); "
                "exiting for restart, uncommitted records will be replayed",
                age,
            )
            logging.shutdown()
            exit_process(EXIT_STALLED)
            return


def main() -> int:
    """Console entry point (``safestream-kafka``): 0 clean stop, 1 Kafka error, 2 bad
    configuration, 3 stalled (see :func:`watchdog`)."""
    configure_logging()
    try:
        config = ConnectorConfig.from_env()
        redactor = build_redactor(config)
    except ValidationError as exc:
        # include_input=False: the rejected value may be a password or key.
        for err in exc.errors(include_input=False, include_url=False):
            logger.error("invalid configuration: %s: %s", err["loc"], err["msg"])
        return 2
    except ValueError as exc:
        logger.error("invalid configuration: %s", exc)
        return 2

    connector = KafkaRedactionConnector(
        config,
        redactor,
        Consumer(config.consumer_config()),
        Producer(config.producer_config()),
    )
    health: HealthServer | None = None
    if config.metrics_port:
        try:
            health = HealthServer(
                connector.snapshot, config.metrics_port, config.liveness_timeout_s
            ).start()
        except OSError as exc:
            logger.error("cannot serve health/metrics on port %d: %s", config.metrics_port, exc)
            return 2
    threading.Thread(
        target=watchdog,
        args=(connector, config.liveness_timeout_s),
        name="safestream-watchdog",
        daemon=True,
    ).start()
    # Kubernetes sends SIGTERM on scale-down/rollout; drain instead of dying mid-batch.
    signal.signal(signal.SIGTERM, connector.stop)
    signal.signal(signal.SIGINT, connector.stop)
    try:
        connector.run()
    except (KafkaException, DeliveryError) as exc:
        logger.critical("unrecoverable Kafka error, exiting for restart: %s", exc)
        return 1
    finally:
        if health is not None:
            health.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
