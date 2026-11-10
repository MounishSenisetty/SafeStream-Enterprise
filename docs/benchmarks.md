# Benchmarks

Measured with `bench/run.py` on SafeStream Enterprise 0.3.0 (safestream-redactor 0.5.0),
CPython 3.13, one core of an Intel Xeon at 2.1 GHz, against a single-node Kafka 4.3 broker on
the same machine. Records are synthetic application log events; every one carries an email
address, a name, an IP address and free text.

| Engine workload | Avg record | Records/s per core | MB/s per core |
|---|---|---|---|
| JSON, small | 368 B | 2,799 | 1.0 |
| JSON, large | 1,790 B | 544 | 1.0 |
| XML event | 302 B | 3,313 | 1.0 |

| End to end (JSON, small; one connector, one partition) | Records/s |
|---|---|
| at_least_once | 2,439 |
| exactly_once | 2,361 |

## Reading the numbers

- **About 1 MB/s per core, whatever the record shape.** Cost follows the bytes scanned, not the
  record count.
- **Kafka is not the bottleneck.** End to end is within 15% of the engine alone, and
  exactly-once costs about 3% over at-least-once.
- **Sizing.** One connector pod handles roughly 2,400 small records per second, about 200
  million a day. Throughput scales with pods up to the ingress topic's partition count, so
  size partitions as peak records per second divided by 2,000.

## Where the time goes

A profile of the small-JSON workload puts over 90% of the time in the open-source engine's
content detectors (`safestream_redactor.Redactor.detect`), which run in pure Python: the
0.5.0 wheel on PyPI is `py3-none-any` and carries no compiled extension, so `backend="auto"`
falls back to Python. JSON parsing, field rules and serialisation in this package account for
under 10%.

So the next step for throughput is in the engine, not in this repository: shipping the engine's
native backend as binary wheels would lift every number above. Until then the lever is
partitions and pods.

## Reproducing

```bash
python bench/run.py --bootstrap localhost:9092
```

CI runs the engine benchmark on every change with a floor of 1,000 records/s for small JSON.
That catches a gross regression; shared CI runners are too noisy for a tighter gate.
