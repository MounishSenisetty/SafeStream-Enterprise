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
    TopicPartition,
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
#: exactly_once: transaction attempts per batch before giving up (and restarting).
MAX_TRANSACTION_ATTEMPTS = 5


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
        if self.transactional_id and self.delivery != "exactly_once":
            raise ValueError(
                "SAFESTREAM_TRANSACTIONAL_ID requires SAFESTREAM_DELIVERY=exactly_once"
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
        if self.config.exactly_once:
            # Registers the transactional.id and aborts any transaction a
            # previous instance with the same id left open.
            self.producer.init_transactions(self.config.flush_timeout_s)
        self.consumer.subscribe([self.config.ingress_topic])
        logger.info(
            "consuming %s -> %s (group=%s, delivery=%s)",
            self.config.ingress_topic,
            self.config.egress_topic,
            self.config.group_id,
            self.config.delivery,
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
        if self.config.exactly_once:
            self._process_transactional(messages)
        else:
            self._process_at_least_once(messages)

    def _publish(self, messages: list[Message]) -> None:
        for msg in messages:
            self.handle_message(msg)
            # Serve delivery callbacks so the local queue keeps draining.
            self.producer.poll(0)

    def _process_at_least_once(self, messages: list[Message]) -> None:
        self._publish(messages)
        remaining = self.producer.flush(self.config.flush_timeout_s)
        if remaining or self._delivery_errors:
            errors = [str(e) for e in self._delivery_errors[:5]]
            self._delivery_errors.clear()
            raise DeliveryError(
                f"{remaining} record(s) unflushed, delivery errors: {errors}; "
                "offsets NOT committed, batch will be replayed after restart"
            )
        # Synchronous: when this returns, a restart resumes after this batch.
        self.consumer.commit(asynchronous=False)

    def _process_transactional(self, messages: list[Message]) -> None:
        """Publish ``messages`` and commit their offsets in one transaction.

        Abortable failures abort and retry the same in-memory batch: the
        consumer position is never rewound because offsets are committed
        explicitly from ``messages``, not from the consumer's position.
        """
        offsets = _next_offsets(messages)
        for attempt in range(1, MAX_TRANSACTION_ATTEMPTS + 1):
            # Counters are restored on abort so a retried batch isn't counted twice.
            saved = (copy.deepcopy(self.stats), self.dead_lettered)
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
                self._delivery_errors.clear()
                self.stats, self.dead_lettered = saved
                continue
            self._delivery_errors.clear()
            return
        raise DeliveryError(
            f"transaction aborted {MAX_TRANSACTION_ATTEMPTS} times; offsets NOT committed, "
            "batch will be replayed after restart"
        )

    def _commit_transaction(self) -> None:
        """Commit, retrying errors librdkafka marks retriable (e.g. a timeout)."""
        for attempt in range(1, MAX_TRANSACTION_ATTEMPTS + 1):
            try:
                self.producer.commit_transaction(self.config.flush_timeout_s)
                return
            except KafkaException as exc:
                if not exc.args[0].retriable() or attempt == MAX_TRANSACTION_ATTEMPTS:
                    raise


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
