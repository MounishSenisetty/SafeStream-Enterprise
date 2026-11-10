"""``safestream-dlq``: inspect the dead-letter topic and replay it through redaction.

    safestream-dlq summary                      # what is in the DLQ, by error
    safestream-dlq replay                       # send it all back to the ingress topic
    safestream-dlq replay --error MSG_SIZE_TOO_LARGE --limit 1000

Dead-lettered records are the *original, unredacted* records. Replay therefore
publishes them to the **ingress** topic, never to the clean topic: they go
through the connector again and are redacted, or dead-lettered again if the
cause has not been fixed.

Configuration comes from the same environment variables as the connector
(brokers, topics, ``SAFESTREAM_KAFKA_*`` client settings), so the tool can run
as a Kubernetes Job from the connector's own image and Secret.

Replay is at-least-once and resumable. It reads to the end of the DLQ as it
stands, waits for the ingress brokers to acknowledge every record, and only
then commits its position under ``--group``; a crash before that replays the
same records on the next run, a later run continues where this one stopped.
Records an ``--error`` filter passes over are not revisited by the same
group: use another ``--group`` to replay them later.

Output is one JSON object of counts on stdout. Like every other SafeStream
output it holds no record content.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from collections.abc import Sequence
from typing import Any

from confluent_kafka import (
    OFFSET_BEGINNING,
    Consumer,
    KafkaError,
    KafkaException,
    Message,
    Producer,
    TopicPartition,
)
from pydantic import ValidationError

from safestream_enterprise.connectors.kafka import ERROR_HEADER, ConnectorConfig, _parts
from safestream_enterprise.logs import configure_logging

logger = logging.getLogger("safestream_enterprise.dlq")

#: Give up if the brokers send nothing (not even end-of-partition) for this long.
IDLE_TIMEOUT_POLLS = 60


class ReplayError(RuntimeError):
    """Replay stopped without committing; the next run repeats it."""


def consumer_config(config: ConnectorConfig, group: str) -> dict[str, Any]:
    return {
        **config.consumer_config(),
        "group.id": group,
        # The run ends when every partition reports its end, not on a timeout.
        "enable.partition.eof": True,
    }


def reason_of(msg: Message) -> str:
    """The error name the connector tagged the record with."""
    headers = msg.headers() or []
    pairs = headers.items() if isinstance(headers, dict) else headers
    for name, value in pairs:
        if name == ERROR_HEADER and value:
            return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    return "unknown"


def run(
    config: ConnectorConfig,
    consumer: Consumer,
    producer: Producer | None,
    error: str | None = None,
    limit: int | None = None,
) -> dict[str, object]:
    """Read the DLQ to its current end; with a ``producer``, replay matching records.

    Without a producer this is ``summary``: it reads from the beginning and
    commits nothing. Raises :class:`ReplayError` if a replayed record was not
    acknowledged, in which case nothing is committed either.
    """
    topic = config.dlq_topic
    metadata = consumer.list_topics(topic, timeout=30).topics[topic]
    if metadata.error is not None:
        raise KafkaException(metadata.error)
    partitions = [TopicPartition(topic, p) for p in metadata.partitions]
    if producer is None:
        for tp in partitions:
            tp.offset = OFFSET_BEGINNING
    # Replay sets no offset, so each partition resumes from this group's
    # committed position (or the beginning for a new group).
    consumer.assign(partitions)

    failures: list[KafkaError] = []

    def on_delivery(err: KafkaError | None, _msg: Message) -> None:
        if err is not None:
            failures.append(err)

    seen: Counter[str] = Counter()
    next_offset: dict[int, int] = {}
    open_partitions = {tp.partition for tp in partitions}
    replayed = idle = 0
    while open_partitions and (limit is None or replayed < limit):
        msg = consumer.poll(1.0)
        if msg is None:
            idle += 1
            if idle >= IDLE_TIMEOUT_POLLS:
                raise ReplayError(f"no response from the brokers for {IDLE_TIMEOUT_POLLS}s")
            continue
        idle = 0
        partition = msg.partition() or 0
        err = msg.error()
        if err is not None:
            if err.code() == KafkaError._PARTITION_EOF:
                open_partitions.discard(partition)
                continue
            raise KafkaException(err)
        reason = reason_of(msg)
        seen[reason] += 1
        next_offset[partition] = (msg.offset() or 0) + 1
        if producer is None or (error is not None and reason != error):
            continue
        value, key, headers, timestamp = _parts(msg)
        while True:
            try:
                producer.produce(
                    config.ingress_topic,
                    value=value,
                    key=key,
                    # Without the error tag: the connector adds a fresh one if it fails again.
                    headers=[h for h in headers if h[0] != ERROR_HEADER],
                    timestamp=timestamp,
                    on_delivery=on_delivery,
                )
                break
            except BufferError:
                producer.poll(1.0)  # local queue full: let deliveries drain
        producer.poll(0)
        replayed += 1

    result: dict[str, object] = {"topic": topic, "records": sum(seen.values())}
    if producer is not None:
        if producer.flush(config.flush_timeout_s) or failures:
            raise ReplayError(
                f"ingress did not acknowledge every record ({failures[:3]}); "
                "nothing committed, run again to repeat"
            )
        if next_offset:
            consumer.commit(
                offsets=[TopicPartition(topic, p, o) for p, o in next_offset.items()],
                asynchronous=False,
            )
        result.update(replayed=replayed, skipped=sum(seen.values()) - replayed)
    result["by_error"] = dict(sorted(seen.items()))
    return result


def main(argv: Sequence[str] | None = None) -> int:
    """Console entry point: 0 ok, 1 Kafka/delivery failure, 2 usage or configuration error."""
    parser = argparse.ArgumentParser(prog="safestream-dlq", description=(__doc__ or "").strip())
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("summary", help="count the records in the DLQ, by error")
    replay = sub.add_parser("replay", help="send DLQ records back to the ingress topic")
    replay.add_argument("--error", help="only records tagged with this error name")
    replay.add_argument("--limit", type=int, help="replay at most this many records")
    replay.add_argument("--group", help="consumer group that tracks replay progress")
    args = parser.parse_args(argv)
    configure_logging()
    try:
        config = ConnectorConfig.from_env()
    except ValidationError as exc:
        for err in exc.errors(include_input=False, include_url=False):
            logger.error("invalid configuration: %s: %s", err["loc"], err["msg"])
        return 2

    replaying = args.command == "replay"
    group = (replaying and args.group) or f"{config.group_id}-dlq-replay"
    consumer = Consumer(consumer_config(config, group))
    # Not transactional: replay is at-least-once whatever the connector's mode.
    producer_config = {k: v for k, v in config.producer_config().items() if k != "transactional.id"}
    producer = Producer(producer_config) if replaying else None
    try:
        result = run(
            config,
            consumer,
            producer,
            error=getattr(args, "error", None),
            limit=getattr(args, "limit", None),
        )
    except (KafkaException, ReplayError) as exc:
        logger.error("%s failed: %s", args.command, exc)
        return 1
    finally:
        consumer.close()
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
