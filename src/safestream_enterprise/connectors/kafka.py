"""Kafka consume -> redact -> produce connector (sidecar or standalone consumer).

Data flow::

    ingress-logs ──consume──▶ StructuredRedactor ──produce──▶ egress-logs-clean
                                      │ (not JSON / redaction raised / egress rejected)
                                      └────────produce──────▶ ingress-logs-dlq

Delivery semantics: **at-least-once, never unredacted to egress.**

* Auto-commit is off. Offsets are committed synchronously only after every
  message in a batch has been *acknowledged* by the egress brokers
  (``acks=all`` + idempotent producer). A crash between produce and commit
  replays the batch: duplicates are possible, loss is not.
* Any delivery failure raises :class:`DeliveryError` and the process exits
  non-zero *without* committing. The orchestrator restarts it and consumption
  resumes from the last committed offset. (Continuing in-process would move the
  in-memory position past the failed messages and a later commit would skip
  them for good.)
* A message that cannot be processed (not valid JSON, redaction raised, or the
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

import logging
import os
import signal
import sys
from collections.abc import Mapping
from types import FrameType
from typing import Literal

from confluent_kafka import (
    TIMESTAMP_NOT_AVAILABLE,
    Consumer,
    KafkaError,
    KafkaException,
    Message,
    Producer,
)
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError, model_validator
from safestream_redactor import RedactionMode, RedactionPolicy, RedactionStats, Redactor

from safestream_enterprise.parsers.json_ast import StructuredRedactor

logger = logging.getLogger("safestream_enterprise.kafka")

#: Prefix for pass-through librdkafka settings (see module docstring).
KAFKA_ENV_PREFIX = "SAFESTREAM_KAFKA_"
#: Header naming which path redacted the record: ``structural`` or ``text``.
MODE_HEADER = "x-safestream-redaction"
#: DLQ header carrying the exception *class* (never its message: it may quote data).
ERROR_HEADER = "x-safestream-error"


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
    #: ``dlq``: a payload that is not valid JSON goes to the DLQ untouched.
    #: ``redact_text``: it is redacted as free text and sent to egress instead.
    non_json: Literal["dlq", "redact_text"] = "dlq"
    #: Extra librdkafka properties applied to both consumer and producer
    #: (security.protocol, sasl.*, ssl.* ...). Secret-wrapped: may hold passwords.
    client_overrides: dict[str, SecretStr] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _check(self) -> ConnectorConfig:
        # A topic collision is a data-safety bug, not a style issue: egress ==
        # ingress loops forever, and dlq == egress publishes raw records to the
        # clean topic.
        topics = (self.ingress_topic, self.egress_topic, self.dlq_topic)
        if len(set(topics)) != len(topics):
            raise ValueError("ingress, egress and DLQ topics must all be different")
        if self.redaction_mode is RedactionMode.PSEUDONYMIZE and not self.hmac_key:
            raise ValueError("pseudonymize mode requires SAFESTREAM_HMAC_KEY")
        return self

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
            "SAFESTREAM_NON_JSON": "non_json",
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
        return {
            "bootstrap.servers": self.bootstrap_servers,
            # Idempotence implies acks=all, unbounded retries, ordered delivery
            # per partition: no duplicates or reordering from producer retries.
            "enable.idempotence": True,
            "acks": "all",
            "compression.type": "zstd",
            "linger.ms": 20,
            **self._overrides(),
        }


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
        self.dead_lettered = 0
        self._running = True
        self._delivery_errors: list[KafkaError] = []

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    def stop(self, signum: int | None = None, _frame: FrameType | None = None) -> None:
        """Request a graceful stop; the current batch finishes and is committed."""
        logger.info("stop requested (signal=%s); draining current batch", signum)
        self._running = False

    def run(self) -> None:
        """Main loop. Returns after :meth:`stop`; raises on unrecoverable errors."""
        self.consumer.subscribe([self.config.ingress_topic])
        logger.info(
            "consuming %s -> %s (group=%s)",
            self.config.ingress_topic,
            self.config.egress_topic,
            self.config.group_id,
        )
        try:
            while self._running:
                batch = self.consumer.consume(
                    num_messages=self.config.batch_size, timeout=self.config.poll_timeout_s
                )
                if batch:
                    self.process_batch(batch)
        finally:
            # Order matters: flush in-flight egress first, then close the consumer
            # (which leaves the group so partitions rebalance immediately).
            self.producer.flush(self.config.flush_timeout_s)
            self.consumer.close()
            logger.info("stopped: %s; dead-lettered=%d", self.stats.summary(), self.dead_lettered)

    # ------------------------------------------------------------------
    # batch processing
    # ------------------------------------------------------------------

    def _on_delivery(self, err: KafkaError | None, _msg: Message) -> None:
        # Runs inside producer.poll()/flush() on this thread: no lock needed.
        if err is not None:
            self._delivery_errors.append(err)

    def _produce(
        self,
        topic: str,
        value: bytes | None,
        key: str | bytes | None,
        headers: list[tuple[str, str | bytes | None]],
        timestamp: int,
    ) -> None:
        """Produce one record, applying backpressure when the local queue is full."""
        while True:
            try:
                self.producer.produce(
                    topic,
                    value=value,
                    key=key,
                    headers=headers,
                    timestamp=timestamp,
                    on_delivery=self._on_delivery,
                )
                return
            except BufferError:
                # librdkafka's queue is full: serve delivery reports to drain it.
                self.producer.poll(1.0)

    def _redact_bytes(self, data: str | bytes) -> bytes:
        """Redact a key or header value (plain text or JSON, never strict)."""
        return self.redactor.redact_line(data).data

    def handle_message(self, msg: Message) -> None:
        """Redact one record and hand it to the producer (not yet acknowledged)."""
        ts_type, ts = msg.timestamp()
        # Preserve event time so downstream windowing/retention is unaffected.
        timestamp = ts if ts_type != TIMESTAMP_NOT_AVAILABLE else 0
        value: bytes | None = msg.value()
        key: str | bytes | None = msg.key()
        headers = msg.headers() or []
        # Consumed messages carry a list; the stubs also allow a dict.
        raw_headers = list(headers.items()) if isinstance(headers, dict) else headers

        try:
            if value is None:
                # Tombstone: nothing to redact, but compacted topics need it forwarded.
                out_value: bytes | None = None
                mode = b"tombstone"
            else:
                # strict: a non-JSON payload raises StructuredParseError -> DLQ.
                record = self.redactor.redact_line(
                    value, self.stats, strict=self.config.non_json == "dlq"
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
            self._produce(self.config.egress_topic, out_value, out_key, out_headers, timestamp)
        except Exception as exc:  # any per-record failure: DLQ, never egress
            self._dead_letter(msg, value, key, raw_headers, timestamp, exc)

    def _dead_letter(
        self,
        msg: Message,
        value: bytes | None,
        key: str | bytes | None,
        headers: list[tuple[str, str | bytes | None]],
        timestamp: int,
        exc: Exception,
    ) -> None:
        """Route the *original* record to the DLQ, tagged with the exception class."""
        # Class name only: exception messages can quote record content.
        logger.error(
            "dead-lettering %s[%s]@%s (%s)",
            msg.topic(),
            msg.partition(),
            msg.offset(),
            type(exc).__name__,
        )
        self.dead_lettered += 1
        self._produce(
            self.config.dlq_topic,
            value,
            key,
            [*headers, (ERROR_HEADER, type(exc).__name__.encode())],
            timestamp,
        )

    def process_batch(self, batch: list[Message]) -> None:
        """Redact and publish a batch, then commit its offsets (all or nothing)."""
        handled = 0
        for msg in batch:
            err = msg.error()
            if err is not None:
                if err.fatal():
                    raise KafkaException(err)
                # Transient broker/partition errors: librdkafka retries itself.
                logger.warning("consumer error: %s", err)
                continue
            self.handle_message(msg)
            handled += 1
            # Serve delivery callbacks so the local queue keeps draining.
            self.producer.poll(0)

        remaining = self.producer.flush(self.config.flush_timeout_s)
        if remaining or self._delivery_errors:
            errors = [str(e) for e in self._delivery_errors[:5]]
            self._delivery_errors.clear()
            raise DeliveryError(
                f"{remaining} record(s) unflushed, delivery errors: {errors}; "
                "offsets NOT committed, batch will be replayed after restart"
            )
        if not handled:
            return  # only error events: no new offsets (commit would raise _NO_OFFSET)
        # Synchronous: when this returns, a restart resumes after this batch.
        # ponytail: at-least-once. Upgrade to exactly-once with a transactional
        # producer + send_offsets_to_transaction() if duplicates downstream matter.
        self.consumer.commit(asynchronous=False)


def build_redactor(config: ConnectorConfig) -> StructuredRedactor:
    """The structured redactor for ``config``.

    ``hmac_key`` keys pseudonymize mode so the same customer maps to the same
    token across every topic and day. Mount it from a Secret; never bake it
    into the image.
    """
    key = config.hmac_key.get_secret_value().encode() if config.hmac_key else None
    policy = RedactionPolicy(mode=config.redaction_mode, hmac_key=key)
    return StructuredRedactor(
        Redactor(
            policy=policy,
            # Compiled Rust core when installed, pure Python otherwise;
            # output is byte-identical either way.
            backend="auto",
            # Third-party detector plugins run with full process privileges
            # inside a service that sees every record: opt-in only.
            load_plugins=False,
        )
    )


def main() -> int:
    """Console entry point (``safestream-kafka``). Exit code 0 on clean stop."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
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
    # Kubernetes sends SIGTERM on scale-down/rollout; drain instead of dying mid-batch.
    signal.signal(signal.SIGTERM, connector.stop)
    signal.signal(signal.SIGINT, connector.stop)
    try:
        connector.run()
    except (KafkaException, DeliveryError) as exc:
        logger.critical("unrecoverable Kafka error, exiting for restart: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
