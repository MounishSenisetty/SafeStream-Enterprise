# Benchmarks

Measured with `bench/run.py` on SafeStream Enterprise 0.3.0+ (safestream-redactor 0.5.0),
CPython 3.13, one core of an Intel Xeon at 2.1 GHz, against a single-node Kafka 4.3 broker on
the same machine. Every record is generated fresh and redacted once (see "The value cache"
below for why that matters). Every record carries personal data.

| Engine workload | Avg record | Records/s per core | MB/s per core | Without the value cache |
|---|---|---|---|---|
| JSON, small: app log with email, name, IP, free text | 368 B | 5,251 | 1.9 | 3,059 |
| JSON, large: the same with 40 more text attributes | 1,790 B | 4,155 | 7.4 | 566 |
| XML event: Windows-style logon event | 301 B | 8,324 | 2.5 | 3,843 |
| JSON, access log: 50 routes, 20 hosts, 10 agents; unique request id and IP | 250 B | 19,069 | 4.8 | 3,415 |

| End to end (JSON, small; one connector, one partition) | Records/s | Without the value cache |
|---|---|---|
| at_least_once | 3,981 | 2,439 |
| exactly_once | 3,828 | 2,361 |

## Reading the numbers

- **Throughput depends on how much your logs repeat.** Values that recur (levels, hosts,
  routes, user agents, status text) are scanned once; unique ones (request ids, addresses,
  free-text messages) every time. Access logs, which are mostly repetition, run five times
  faster than before the cache; application logs with a unique message per line, about 1.7
  times. The large-JSON gain overstates real logs: its synthetic attributes draw on an
  eleven-word vocabulary, so they repeat far more than real text would.
- **Kafka is not the bottleneck.** End to end is within about 25% of the engine alone, and
  exactly-once costs about 4% over at-least-once.
- **Sizing.** Measure your own records (below). As a starting point, one connector pod
  handles about 3,800 small application-log records per second, about 330 million a day.
  Throughput scales with pods up to the ingress topic's partition count.

## The value cache

Most of the time goes to the open-source engine's content detectors
(`safestream_redactor.Redactor.detect`), which run in pure Python: the 0.5.0 wheel on PyPI is
`py3-none-any`, so `backend="auto"` falls back to Python. Each call costs about 20 µs before
it has looked at a single character, and a record is scanned one value at a time, so on short
values most of the cost was that fixed overhead.

So each redactor remembers the result for values up to 256 characters: the redacted text and
the entity types found, keyed by a 128-bit BLAKE2b digest of the value. The value itself is
not kept, since it may be personal data. The engine's output for a given string never changes,
so a cache hit is exactly what scanning again would give, and redaction counts stay exact. A
property test checks output and counts against an uncached redactor in every mode. Up to
65,536 entries (a few MB); the cache starts over when full, and a new policy builds a new
redactor with an empty one.

Joining a record's values into one call would cut the overhead further, but neighbouring text
can change what the detectors find, and a missed detection is not an acceptable price for speed.

The next step for throughput is still in the engine, not in this repository: shipping its
native backend as binary wheels would lift every number above.

## Reproducing

```bash
python bench/run.py --bootstrap localhost:9092
```

CI runs the engine benchmark on every change with a floor of 1,000 records/s for small JSON.
That catches a gross regression; shared CI runners are too noisy for a tighter gate.

## Control plane

Measured with `control-plane/load/fleet.mjs` against the Worker under `wrangler dev --env
local`: one `workerd` process with D1 on a local SQLite file, on a 4-core machine that also
ran the load generator. Each simulated connector polls the active and the candidate policy
(conditional requests) and reports one audit event, at a multiple of the real cadence (every
30 s and every 60 s). The fleet column is the real-speed fleet the run stands for; the offered
load is about fleet ÷ 12 requests per second. 30 s per run, after every connector had reported
once.

| Fleet | During a rollout | Requests/s served | Active policy p50 / p95 / p99 (ms) | Telemetry p50 / p95 / p99 (ms) | Errors |
|---|---|---|---|---|---|
| 1,000 | no | 83 | 17 / 29 / 37 | 15 / 26 / 35 | 0 |
| 1,000 | yes | 83 | 19 / 35 / 70 | 17 / 31 / 75 | 0 |
| 2,000 | no | 167 | 32 / 101 / 167 | 33 / 101 / 164 | 0 |
| 2,000 | yes | 166 | 64 / 205 / 250 | 66 / 211 / 250 | 0 |
| 3,000 | no | 250 | 486 / 1,044 / 1,139 | 558 / 1,056 / 1,184 | 0 |
| 3,000 | yes | 222 (of about 250 offered) | 2,055 / 3,536 / 3,872 | 2,063 / 3,554 / 3,877 | 0 |

**Reading the numbers.**

- **This is one isolate, not the edge.** A single local `workerd` saturates at about 300
  requests a second. At 3,000 connectors it is near that without a rollout, and past it
  during one (222 of 250 served), so latency there is mostly queueing. In
  production, requests spread over many isolates and locations, so the ceiling is D1's, not one
  process's. These numbers bound the per-request cost of the handlers and show where the cost
  grows, not a production capacity.
- **A rollout costs about double per request at 2,000 connectors.** Every active-policy request
  during a rollout also looks up the cohort. Before this phase it read and hashed every live
  connector on each request, and served half the throughput (154 against 317 requests a second
  at 5,000 simulated connectors, overloaded). The cohort is now cached per stage for 15 seconds.
- **No errors at any load measured**, including a run held above saturation: requests queue,
  none fail. CI runs a short version of this test on every change and fails on any error.
- **What design partners need is far below this.** A partner with 50 connectors makes about 4
  requests a second.

To reproduce, start the Worker as in `control-plane/README.md`, then:

```bash
node load/fleet.mjs --url http://127.0.0.1:8787 --platform-token "$PLATFORM_ADMIN_TOKEN" --connectors 500 --speedup 4 --seconds 30 --rollout
```
