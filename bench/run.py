"""SafeStream Enterprise benchmark: records per second on one core.

    python bench/run.py                              # engine only
    python bench/run.py --bootstrap localhost:9092   # + end to end through Kafka
    python bench/run.py --min-rate 2000              # exit 1 if JSON falls below (CI gate)

Engine numbers time ``StructuredRedactor.redact_line`` alone. End-to-end numbers
time the connector from a pre-filled ingress topic until the last record is
committed, so they include consume, redact, produce, acknowledgement and commit.
Records are synthetic and deterministic (fixed seed); every one carries PII.
"""

from __future__ import annotations

import argparse
import json
import platform
import random
import sys
import threading
import time
import uuid
from collections.abc import Callable

from safestream_enterprise import StructuredRedactor, __version__

WORDS = [
    "request",
    "handled",
    "upstream",
    "timeout",
    "retry",
    "cache",
    "miss",
    "shard",
    "replica",
    "queue",
    "flush",
]


def json_record(rng: random.Random, fields: int) -> bytes:
    """An application log event; ``fields`` extra plain attributes set its size."""
    user = f"user{rng.randrange(10**6)}"
    record = {
        "ts": "2026-11-10T08:00:00.000Z",
        "level": rng.choice(["info", "warn", "error"]),
        "service": rng.choice(["checkout", "auth", "search"]),
        "trace_id": f"{rng.getrandbits(64):016x}",
        "email": f"{user}@corp.example",
        "LastName": rng.choice(["Smith", "Garcia", "Chen"]),
        "client_ip": f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}",
        "msg": f"{' '.join(rng.choices(WORDS, k=8))} for {user}@corp.example",
        "attrs": {f"k{i}": " ".join(rng.choices(WORDS, k=4)) for i in range(fields)},
    }
    return json.dumps(record).encode()


def xml_record(rng: random.Random) -> bytes:
    """A Windows Event Log style record."""
    return (
        "<Event><System><EventID>4624</EventID><Computer>dc01</Computer></System><EventData>"
        f'<Data Name="TargetUserName">user{rng.randrange(10**6)}</Data>'
        f'<Data Name="IpAddress">10.0.{rng.randrange(256)}.{rng.randrange(256)}</Data>'
        f'<Data Name="LogonType">{rng.randrange(12)}</Data>'
        f'<Data Name="Detail">{" ".join(rng.choices(WORDS, k=8))}</Data>'
        "</EventData></Event>"
    ).encode()


ROUTES = [
    f"/api/v1/{r}/{a}"
    for r in ("orders", "users", "carts", "search", "items")
    for a in "abcdefghij"
]
HOSTS = [f"web-{i:02d}.prod.internal" for i in range(20)]
AGENTS = [f"Mozilla/5.0 (client {i})" for i in range(10)]


def access_record(rng: random.Random) -> bytes:
    """An HTTP access-log event: 50 routes, 20 hosts, 10 agents, a handful of
    statuses and methods; the request id and client IP are unique."""
    return json.dumps(
        {
            "ts": "2026-11-10T08:00:00.000Z",
            "request_id": f"{rng.getrandbits(64):016x}",
            "method": rng.choice(["GET", "GET", "GET", "POST", "PUT", "DELETE"]),
            "path": rng.choice(ROUTES),
            "status": rng.choice([200, 200, 200, 201, 204, 301, 404, 500]),
            "host": rng.choice(HOSTS),
            "user_agent": rng.choice(AGENTS),
            "client_ip": f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}",
            "duration_ms": rng.randrange(2000),
        }
    ).encode()


WORKLOADS: dict[str, Callable[[random.Random], bytes]] = {
    "JSON, small": lambda rng: json_record(rng, 2),
    "JSON, large": lambda rng: json_record(rng, 40),
    "XML event": xml_record,
    "JSON, access log": access_record,
}


def bench_engine(make: Callable[[random.Random], bytes], seconds: float) -> dict[str, float]:
    """Every record is generated fresh and redacted once: replaying the same
    records would turn the redactor's value cache into a false speedup."""
    rng = random.Random(7)
    redactor = StructuredRedactor()
    for _ in range(200):  # warm-up: imports, compiled patterns
        redactor.redact_line(make(random.Random(rng.random())))
    done = size = 0
    elapsed = 0.0
    while elapsed < seconds:
        chunk = [make(rng) for _ in range(1000)]  # generated outside the timing
        started = time.perf_counter()
        for r in chunk:
            redactor.redact_line(r)
        elapsed += time.perf_counter() - started
        done += len(chunk)
        size += sum(map(len, chunk))
    return {"bytes": size / done, "rate": done / elapsed, "mb_s": size / elapsed / 1e6}


def bench_kafka(bootstrap: str, delivery: str, n: int) -> float:
    from confluent_kafka import Consumer, Producer
    from confluent_kafka.admin import AdminClient, NewTopic

    from safestream_enterprise.connectors.kafka import (
        ConnectorConfig,
        KafkaRedactionConnector,
        build_redactor,
    )

    run = uuid.uuid4().hex[:8]
    topics = {k: f"bench-{k}-{run}" for k in ("ingress", "egress", "dlq")}
    admin = AdminClient({"bootstrap.servers": bootstrap})
    for future in admin.create_topics([NewTopic(t, 1, 1) for t in topics.values()]).values():
        future.result(30)
    rng = random.Random(7)
    producer = Producer({"bootstrap.servers": bootstrap, "linger.ms": 20})
    for _ in range(n):
        producer.produce(topics["ingress"], WORKLOADS["JSON, small"](rng))
        producer.poll(0)
    assert producer.flush(120) == 0

    config = ConnectorConfig(
        bootstrap_servers=bootstrap,
        group_id=f"bench-{run}",
        ingress_topic=topics["ingress"],
        egress_topic=topics["egress"],
        dlq_topic=topics["dlq"],
        delivery=delivery,  # type: ignore[arg-type]
        metrics_port=0,
    )
    connector = KafkaRedactionConnector(
        config,
        build_redactor(config),
        Consumer(config.consumer_config()),
        Producer(config.producer_config()),
    )
    thread = threading.Thread(target=connector.run, daemon=True)
    thread.start()
    while connector.egress_records == 0:  # exclude group join from the timing
        time.sleep(0.005)
    first, started = connector.egress_records, time.perf_counter()
    while connector.snapshot().egress_records < n and thread.is_alive():
        time.sleep(0.02)
    rate = (connector.egress_records - first) / (time.perf_counter() - started)
    connector.stop()
    thread.join(60)
    admin.delete_topics(list(topics.values()))
    return rate


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--seconds", type=float, default=5.0, help="per engine workload")
    parser.add_argument("--bootstrap", help="Kafka broker for the end-to-end runs")
    parser.add_argument("--records", type=int, default=200_000, help="per end-to-end run")
    parser.add_argument("--min-rate", type=float, help="fail if 'JSON, small' is slower (rec/s)")
    args = parser.parse_args()

    print(
        f"SafeStream Enterprise {__version__}, Python {platform.python_version()}, "
        f"{platform.machine()}\n"
    )
    print("| Engine workload | Avg record | Records/s per core | MB/s per core |")
    print("|---|---|---|---|")
    results = {name: bench_engine(make, args.seconds) for name, make in WORKLOADS.items()}
    for name, r in results.items():
        print(f"| {name} | {r['bytes']:.0f} B | {r['rate']:,.0f} | {r['mb_s']:.1f} |")
    if args.bootstrap:
        print("\n| End to end (JSON, small; one connector, one partition) | Records/s |")
        print("|---|---|")
        for delivery in ("at_least_once", "exactly_once"):
            rate = bench_kafka(args.bootstrap, delivery, args.records)
            print(f"| {delivery} | {rate:,.0f} |")
    floor = args.min_rate
    if floor and results["JSON, small"]["rate"] < floor:
        print(f"\nFAIL: JSON, small below the floor of {floor:,.0f} rec/s", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
