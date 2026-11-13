// Load test of the control plane: a simulated fleet of connectors doing what
// real ones do, at a multiple of their real cadence.
//
//   node load/fleet.mjs --url http://127.0.0.1:8787 --platform-token <token> \
//       --connectors 500 --speedup 10 --seconds 30 [--rollout]
//
// A real connector asks for the active and the candidate policy every 30 s
// (conditional requests: 304 when unchanged) and reports one audit event a
// minute. --speedup 10 runs the fleet ten times faster than that, so 500
// connectors at 10x stand for 5,000 at real speed. --rollout runs it during
// a staged rollout, the expensive path: the Worker works out the cohort on
// every active-policy request.
//
// Prints a JSON report: requests per second, latency percentiles per route,
// and every non-2xx/304 response. Exit code 1 if any request failed.

import { createRequire } from "node:module";

// A bounded, keep-alive connection pool: real connectors are separate
// machines, and an unbounded pool would measure this host's file-descriptor
// limit (and crash a local workerd with "Too many open files"), not the Worker.
// undici is wrangler's own HTTP client, so it is already installed with it.
const { Agent, fetch } = createRequire(import.meta.url)("undici");
const dispatcher = new Agent({ connections: Number(process.env.LOAD_CONNECTIONS ?? 64) });

const args = Object.fromEntries(
  process.argv.slice(2).reduce((pairs, arg, i, all) => {
    if (arg.startsWith("--")) pairs.push([arg.slice(2), all[i + 1]?.startsWith("--") || all[i + 1] === undefined ? "true" : all[i + 1]]);
    return pairs;
  }, []),
);
const URL_ = args.url ?? "http://127.0.0.1:8787";
const PLATFORM = args["platform-token"] ?? process.env.PLATFORM_ADMIN_TOKEN;
const CONNECTORS = Number(args.connectors ?? 200);
const SPEEDUP = Number(args.speedup ?? 10);
const SECONDS = Number(args.seconds ?? 30);
const ROLLOUT = args.rollout === "true";
if (!PLATFORM) {
  console.error("--platform-token (or PLATFORM_ADMIN_TOKEN) is required");
  process.exit(2);
}

async function call(method, path, token, body, headers = {}) {
  const started = performance.now();
  const response = await fetch(URL_ + path, {
    dispatcher,
    method,
    headers: { authorization: `Bearer ${token}`, ...(body ? { "content-type": "application/json" } : {}), ...headers },
    body,
  });
  const text = await response.text();
  return { status: response.status, ms: performance.now() - started, text, etag: response.headers.get("etag") };
}

async function must(method, path, token, body) {
  const r = await call(method, path, token, body === undefined ? undefined : JSON.stringify(body));
  if (r.status >= 300) throw new Error(`${method} ${path}: HTTP ${r.status} ${r.text}`);
  return JSON.parse(r.text);
}

const sha256 = async (text) => "sha256:" + Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))).toString("hex");

// ---------------------------------------------------------------- setup

const tenantId = `load-${Date.now().toString(36)}`;
const tenant = await must("POST", "/v1/admin/tenants", PLATFORM, { id: tenantId, name: "Load test" });
const admin = tenant.admin_token;
const agent = (await must("POST", "/v1/agent-tokens", admin, { label: "load" })).token;
await must("POST", "/v1/policies", admin, { field_rules: { rules: {} } });
await must("POST", "/v1/policies/1/promote", admin, { strategy: "immediate" });
await must("POST", "/v1/policies", admin, { field_rules: { rules: { "*member_id*": "id_number" } } });

const fleet = Array.from({ length: CONNECTORS }, (_, i) => ({ instance: `load-pod-${i}`, seq: 0, prev: null, etags: {} }));

function event(c) {
  return JSON.stringify({
    schema: "safestream.audit/v2",
    connector_version: "0.3.0",
    instance: c.instance,
    group_id: "safestream-redactor",
    topics: { ingress: "ingress-logs", egress: "egress-logs-clean", dlq: "ingress-logs-dlq" },
    delivery: "exactly_once",
    redaction_mode: "pseudonymize",
    field_rules: { count: 66, fingerprint: "sha256:" + "ab".repeat(32) },
    policy: { tenant: tenantId, version: 1, key_id: tenant.key_id },
    shadow: {
      candidate: { tenant: tenantId, version: 2, key_id: tenant.key_id },
      since: "2026-11-12T09:00:00+00:00",
      records: 1000,
      changed_records: 40,
      errors: 0,
      redactions: { active: { email: 1000 }, candidate: { email: 1000, id_number: 40 } },
    },
    chain: { id: `${c.instance}-chain`, seq: c.seq, prev: c.prev },
    window: { start: new Date(Date.now() - 60_000).toISOString(), end: new Date().toISOString(), final: false },
    records: { egress: 48_000, dlq: 2 },
    redactions: { email: 9000, person: 4000 },
    batches: 97,
    transaction_aborts: 0,
    canary: { checks: 2, leaks: 0 },
  });
}

const samples = { "policy/active": [], "policy/candidate": [], telemetry: [] };
const failures = [];

async function report(c) {
  const body = event(c);
  const r = await call("POST", "/v1/agent/telemetry", agent, body);
  samples.telemetry.push(r.ms);
  if (r.status !== 202 && r.status !== 200) failures.push({ route: "telemetry", status: r.status, body: r.text.slice(0, 200) });
  else {
    c.seq += 1;
    c.prev = await sha256(body);
  }
}

async function poll(c, which) {
  const headers = { "x-safestream-instance": c.instance, ...(c.etags[which] ? { "if-none-match": c.etags[which] } : {}) };
  const r = await call("GET", `/v1/agent/policy/${which}`, agent, undefined, headers);
  samples[`policy/${which}`].push(r.ms);
  if (r.status === 200) c.etags[which] = r.etag;
  else if (r.status !== 304) failures.push({ route: `policy/${which}`, status: r.status, body: r.text.slice(0, 200) });
}

// Every connector reports once, so the fleet is "live" (a rollout's cohort is drawn from live connectors).
for (let i = 0; i < fleet.length; i += 50) await Promise.all(fleet.slice(i, i + 50).map(report));
if (ROLLOUT) await must("POST", "/v1/policies/2/promote", admin, { soak_seconds: 3600 });
for (const k of Object.keys(samples)) samples[k].length = 0;
failures.length = 0;

// ---------------------------------------------------------------- run

const pollEveryMs = 30_000 / SPEEDUP;
const reportEveryMs = 60_000 / SPEEDUP;
const until = Date.now() + SECONDS * 1000;
const inFlight = new Set();
const track = (p) => {
  inFlight.add(p);
  p.finally(() => inFlight.delete(p));
};
const started = performance.now();
// Spread each connector's schedule over its period, as independent pods would be.
const timers = fleet.flatMap((c, i) => {
  const pollOffset = (pollEveryMs * i) / fleet.length;
  const reportOffset = (reportEveryMs * i) / fleet.length;
  return [
    setTimeout(function tick() {
      if (Date.now() >= until) return;
      track(poll(c, "active"));
      track(poll(c, "candidate"));
      timers.push(setTimeout(tick, pollEveryMs));
    }, pollOffset),
    setTimeout(function tick() {
      if (Date.now() >= until) return;
      track(report(c));
      timers.push(setTimeout(tick, reportEveryMs));
    }, reportOffset),
  ];
});
await new Promise((resolve) => setTimeout(resolve, SECONDS * 1000));
await Promise.allSettled([...inFlight]);
const elapsed = (performance.now() - started) / 1000;

const pct = (values, p) => {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round(sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] * 10) / 10;
};
const total = Object.values(samples).reduce((n, v) => n + v.length, 0);
const out = {
  url: URL_,
  connectors: CONNECTORS,
  speedup: SPEEDUP,
  equivalent_fleet: CONNECTORS * SPEEDUP,
  during_rollout: ROLLOUT,
  seconds: Math.round(elapsed * 10) / 10,
  requests: total,
  requests_per_second: Math.round(total / elapsed),
  latency_ms: Object.fromEntries(
    Object.entries(samples).map(([route, v]) => [route, { n: v.length, p50: pct(v, 50), p95: pct(v, 95), p99: pct(v, 99), max: pct(v, 100) }]),
  ),
  failures: failures.length,
  first_failures: failures.slice(0, 5),
};
console.log(JSON.stringify(out, null, 2));
process.exit(failures.length ? 1 : 0);
