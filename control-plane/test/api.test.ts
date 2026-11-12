import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const BASE = "https://api.test";

async function call(method: string, path: string, token?: string, body?: unknown, headers: Record<string, string> = {}) {
  const response = await SELF.fetch(BASE + path, {
    method,
    headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  const text = await response.text();
  let data: any = text;
  try {
    data = JSON.parse(text);
  } catch {}
  return { status: response.status, data, text, headers: response.headers };
}

let counter = 0;
/** A fresh tenant with an admin token and one agent token. */
async function tenant(prefix = "acme") {
  const id = `${prefix}-${++counter}-${crypto.randomUUID().slice(0, 6)}`;
  const created = await call("POST", "/v1/admin/tenants", "test-platform-admin-token", { id, name: "Acme Inc" });
  expect(created.status).toBe(201);
  const agent = await call("POST", "/v1/agent-tokens", created.data.admin_token, { label: "prod cluster" });
  expect(agent.status).toBe(201);
  return { id, admin: created.data.admin_token as string, agent: agent.data.token as string, publicKey: created.data.public_key as string, keyId: created.data.key_id as string };
}

const RULES = { mode: "extend", rules: { "*loyalty_number*": "id_number" }, disable: [] };
/** Promote for everyone at once (the default is a staged rollout). */
const IMMEDIATE = { strategy: "immediate" };

const sha256 = async (text: string) =>
  "sha256:" + [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)))].map((b) => b.toString(16).padStart(2, "0")).join("");

/** An audit event as a connector publishes it. */
function event(tenantId: string, seq: number, prev: string | null, extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    schema: "safestream.audit/v2",
    connector_version: "0.3.0",
    instance: "safestream-kafka-redactor-7d9f8-x2k4q",
    group_id: "safestream-redactor",
    topics: { ingress: "ingress-logs", egress: "egress-logs-clean", dlq: "ingress-logs-dlq" },
    delivery: "exactly_once",
    redaction_mode: "pseudonymize",
    field_rules: { count: 68, fingerprint: "sha256:" + "ab".repeat(32) },
    policy: { tenant: tenantId, version: 1, key_id: "9a41c0de52b7f310" },
    shadow: null,
    chain: { id: "pod-a-20261111T090000000000Z", seq, prev },
    window: { start: "2026-11-11T09:00:00.000+00:00", end: "2026-11-11T09:01:00.000+00:00", final: false },
    records: { egress: 48210, dlq: 3 },
    redactions: { email: 9120, person: 4471 },
    batches: 97,
    transaction_aborts: 0,
    ...extra,
  });
}

describe("access", () => {
  it("answers health checks without credentials and nothing else", async () => {
    expect((await call("GET", "/healthz")).data).toEqual({ ok: true });
    expect((await call("GET", "/v1/policies")).status).toBe(401);
    expect((await call("GET", "/v1/policies", "sst_admin_not-a-real-token")).status).toBe(401);
    expect((await call("GET", "/v1/nope")).status).toBe(404);
    expect((await call("DELETE", "/v1/policies")).status).toBe(405);
  });

  it("only the platform admin creates tenants", async () => {
    const t = await tenant();
    const body = { id: "intruder-co", name: "Intruder" };
    expect((await call("POST", "/v1/admin/tenants", t.admin, body)).status).toBe(403);
    expect((await call("POST", "/v1/admin/tenants", "wrong", body)).status).toBe(403);
    expect((await call("POST", "/v1/admin/tenants", "test-platform-admin-token", { id: "Bad Id!", name: "x" })).status).toBe(422);
    const dup = await call("POST", "/v1/admin/tenants", "test-platform-admin-token", { id: t.id, name: "Again" });
    expect(dup.status).toBe(409);
  });

  it("agent tokens cannot administer, admin tokens cannot act as agents", async () => {
    const t = await tenant();
    expect((await call("POST", "/v1/policies", t.agent, { field_rules: RULES })).status).toBe(403);
    expect((await call("GET", "/v1/agents", t.agent)).status).toBe(403);
    expect((await call("GET", "/v1/agent/policy/active", t.admin)).status).toBe(403);
    expect((await call("POST", "/v1/agent/telemetry", t.admin, event(t.id, 0, null))).status).toBe(403);
  });

  it("a revoked token stops working at once", async () => {
    const t = await tenant();
    const tokens = await call("GET", "/v1/tokens", t.admin);
    const agent = tokens.data.tokens.find((x: any) => x.kind === "agent");
    expect(JSON.stringify(tokens.data)).not.toContain(t.agent); // tokens are never listed back
    expect((await call("POST", `/v1/tokens/${agent.id}/revoke`, t.admin)).status).toBe(200);
    expect((await call("GET", "/v1/agent/policy/active", t.agent)).status).toBe(401);
    expect((await call("POST", `/v1/tokens/${agent.id}/revoke`, t.admin)).status).toBe(404);
  });

  it("stores neither tokens nor signing keys in the clear", async () => {
    const t = await tenant();
    const dump = JSON.stringify([
      (await env.DB.prepare("SELECT * FROM tokens").all()).results,
      (await env.DB.prepare("SELECT * FROM tenants").all()).results,
    ]);
    expect(dump).not.toContain(t.admin);
    expect(dump).not.toContain(t.agent);
    expect(dump).not.toContain("PRIVATE");
  });
});

describe("policies", () => {
  it("publishes as candidate, promotes to active, and serves each to agents", async () => {
    const t = await tenant();
    expect((await call("GET", "/v1/agent/policy/active", t.agent)).status).toBe(404);

    const first = await call("POST", "/v1/policies", t.admin, { field_rules: RULES });
    expect(first.status).toBe(201);
    expect(first.data).toMatchObject({ version: 1, state: "candidate", key_id: t.keyId, rules: 1 });
    // Evaluated in shadow first: served as the candidate, not yet as the policy.
    expect((await call("GET", "/v1/agent/policy/candidate", t.agent)).status).toBe(200);
    expect((await call("GET", "/v1/agent/policy/active", t.agent)).status).toBe(404);

    expect((await call("POST", "/v1/policies/1/promote", t.admin, IMMEDIATE)).data).toEqual({ version: 1, state: "active" });
    const active = await call("GET", "/v1/agent/policy/active", t.agent);
    expect(active.status).toBe(200);
    expect((await call("GET", "/v1/agent/policy/candidate", t.agent)).status).toBe(404);
    expect(await sha256(active.text)).toBe(first.data.digest);

    // Unchanged policy: the agent's conditional request costs no body.
    const again = await call("GET", "/v1/agent/policy/active", t.agent, undefined, { "if-none-match": active.headers.get("etag")! });
    expect(again.status).toBe(304);
  });

  it("signs bundles a connector can verify, and versions only go up", async () => {
    const t = await tenant();
    await call("POST", "/v1/policies", t.admin, { field_rules: RULES });
    await call("POST", "/v1/policies", t.admin, { field_rules: { rules: {} } });
    const bundle = (await call("GET", "/v1/agent/policy/candidate", t.agent)).data;
    expect(bundle.schema).toBe("safestream.policy/v1");
    const payloadBytes = Uint8Array.from(atob(bundle.payload), (c) => c.charCodeAt(0));
    const payload = JSON.parse(new TextDecoder().decode(payloadBytes));
    expect(payload).toMatchObject({ tenant: t.id, version: 2, field_rules: { rules: {} } });

    // Verify the signature with the public key the tenant was given.
    const key = await crypto.subtle.importKey("raw", Uint8Array.from(atob(t.publicKey), (c) => c.charCodeAt(0)), "Ed25519", false, ["verify"]);
    const [signature] = bundle.signatures;
    expect(signature).toMatchObject({ key_id: t.keyId, algorithm: "ed25519" });
    const sig = Uint8Array.from(atob(signature.signature), (c) => c.charCodeAt(0));
    expect(await crypto.subtle.verify("Ed25519", key, sig, payloadBytes)).toBe(true);

    await call("POST", "/v1/policies/2/promote", t.admin, IMMEDIATE);
    // Rollback and unknown versions are refused.
    expect((await call("POST", "/v1/policies/1/promote", t.admin, IMMEDIATE)).status).toBe(409);
    expect((await call("POST", "/v1/policies/2/promote", t.admin, IMMEDIATE)).status).toBe(409);
    expect((await call("POST", "/v1/policies/9/promote", t.admin, IMMEDIATE)).status).toBe(409);
    const list = await call("GET", "/v1/policies", t.admin);
    expect(list.data).toMatchObject({ active_version: 2, candidate_version: null });
    expect(list.data.policies.map((p: any) => p.version)).toEqual([2, 1]);
  });

  it("a candidate can be withdrawn", async () => {
    const t = await tenant();
    await call("POST", "/v1/policies", t.admin, { field_rules: RULES });
    expect((await call("POST", "/v1/policies/candidate/withdraw", t.admin)).status).toBe(200);
    expect((await call("GET", "/v1/agent/policy/candidate", t.agent)).status).toBe(404);
  });

  it.each([
    [{ field_rules: { rules: { "*x*": "Not An Entity" } } }],
    [{ field_rules: { rules: { "": "secret" } } }],
    [{ field_rules: { mode: "replace", rules: {} } }],
    [{ field_rules: { rules: {}, surprise: true } }],
    [{ field_rules: RULES, version: 99 }],
    [{}],
  ])("refuses a malformed policy %#", async (bad) => {
    const t = await tenant();
    expect((await call("POST", "/v1/policies", t.admin, bad)).status).toBe(422);
  });
});

describe("telemetry", () => {
  it("anchors the audit chain and shows the fleet", async () => {
    const t = await tenant();
    const e0 = event(t.id, 0, null);
    const e1 = event(t.id, 1, await sha256(e0), { window: { start: "2026-11-11T09:01:00.000+00:00", end: "2026-11-11T09:02:00.000+00:00", final: true } });
    const r0 = await call("POST", "/v1/agent/telemetry", t.agent, e0);
    expect(r0.status).toBe(202);
    expect(r0.data.head).toBe(await sha256(e0));
    // A retry of the same event is accepted and changes nothing.
    expect((await call("POST", "/v1/agent/telemetry", t.agent, e0)).data).toMatchObject({ duplicate: true });
    expect((await call("POST", "/v1/agent/telemetry", t.agent, e1)).status).toBe(202);

    const chains = (await call("GET", "/v1/chains", t.admin)).data.chains;
    expect(chains).toHaveLength(1);
    expect(chains[0]).toMatchObject({ events: 2, head: await sha256(e1), closed: 1, broken: 0 });
    const agents = (await call("GET", "/v1/agents", t.admin)).data.agents;
    expect(agents).toMatchObject([{ instance: "safestream-kafka-redactor-7d9f8-x2k4q", connector_version: "0.3.0", policy_version: 1 }]);
    // The events themselves are kept, byte for byte, as evidence.
    const stored = await env.AUDIT.list({ prefix: `tenants/${t.id}/chains/` });
    expect(stored.objects).toHaveLength(2);
    expect(await (await env.AUDIT.get(stored.objects[0]!.key))!.text()).toBe(e0);
  });

  it("flags a chain when an event is missing or altered", async () => {
    const t = await tenant();
    const e0 = event(t.id, 0, null);
    await call("POST", "/v1/agent/telemetry", t.agent, e0);
    // Event 1 never arrives; event 2 does.
    const gap = await call("POST", "/v1/agent/telemetry", t.agent, event(t.id, 2, "sha256:" + "cd".repeat(32)));
    expect(gap.status).toBe(409);
    expect(gap.data.error).toBe("chain_break");
    // An event chained to something other than the recorded head.
    const forged = await call("POST", "/v1/agent/telemetry", t.agent, event(t.id, 1, "sha256:" + "ef".repeat(32)));
    expect(forged.status).toBe(409);
    const [chain] = (await call("GET", "/v1/chains", t.admin)).data.chains;
    expect(chain).toMatchObject({ broken: 1, events: 1, head: await sha256(e0) });
  });

  // The control plane's one hard rule: nothing that could be record content.
  it.each([
    ["an unknown field", { note: "customer bob@corp.example called" }],
    ["free text where a name is expected", { instance: "pod with spaces and a secret" }],
    ["a nested unknown field", { records: { egress: 1, dlq: 0, sample: "L-4242-77" } }],
    ["an entity name that is not a name", { redactions: { "bob@corp.example": 1 } }],
    ["a count that is not a number", { batches: "many" }],
    ["text in the shadow report", { shadow: { candidate: { tenant: "acme", version: 2, key_id: "9a41c0de52b7f310" }, since: "yesterday", records: 1, changed_records: 0, errors: 0, redactions: { active: {}, candidate: {} } } }],
    ["a v1 event", { schema: "safestream.audit/v1" }],
  ])("refuses telemetry with %s", async (_name, change) => {
    const t = await tenant();
    const response = await call("POST", "/v1/agent/telemetry", t.agent, event(t.id, 0, null, change));
    expect(response.status).toBe(422);
    expect((await env.AUDIT.list({ prefix: `tenants/${t.id}/` })).objects).toHaveLength(0);
    // The reason names the field, never echoes the value.
    expect(response.text).not.toMatch(/bob@corp|L-4242|secret/);
  });

  it("refuses an event about another tenant's policy, and oversized or non-JSON bodies", async () => {
    const t = await tenant();
    expect((await call("POST", "/v1/agent/telemetry", t.agent, event("someone-else", 0, null))).status).toBe(422);
    expect((await call("POST", "/v1/agent/telemetry", t.agent, "not json")).status).toBe(400);
    expect((await call("POST", "/v1/agent/telemetry", t.agent, "x".repeat(70_000))).status).toBe(413);
  });
});

/** A connector that reports audit windows under its own chain, as the Python one does. */
function connector(t: Awaited<ReturnType<typeof tenant>>, instance: string) {
  let seq = 0;
  let prev: string | null = null;
  return {
    instance,
    /** Its "active" bundle, as served to it now: the payload's version, or null. */
    async served(): Promise<number | null> {
      const r = await call("GET", "/v1/agent/policy/active", t.agent, undefined, { "x-safestream-instance": instance });
      if (r.status === 404) return null;
      const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(r.data.payload), (c) => c.charCodeAt(0))));
      return payload.version;
    },
    async report(version: number, extra: { egress?: number; dlq?: number; leaks?: number } = {}) {
      const body = event(t.id, seq, prev, {
        instance,
        chain: { id: `${instance}-chain`, seq, prev },
        policy: { tenant: t.id, version, key_id: t.keyId },
        records: { egress: extra.egress ?? 500, dlq: extra.dlq ?? 0 },
        canary: { checks: 2, leaks: extra.leaks ?? 0 },
      });
      const r = await call("POST", "/v1/agent/telemetry", t.agent, body);
      expect(r.status).toBe(202);
      seq += 1;
      prev = await sha256(body);
    },
  };
}

/** A tenant on version 1 everywhere, with `n` connectors reporting, and version 2 published. */
async function fleet(n: number) {
  const t = await tenant("fleet");
  await call("POST", "/v1/policies", t.admin, { field_rules: { rules: {} } });
  await call("POST", "/v1/policies/1/promote", t.admin, IMMEDIATE);
  const agents = Array.from({ length: n }, (_, i) => connector(t, `pod-${i}`));
  for (const a of agents) await a.report(1, { egress: 1000, dlq: 2 });
  await call("POST", "/v1/policies", t.admin, { field_rules: RULES });
  return { t, agents };
}

const servedVersions = async (agents: ReturnType<typeof connector>[]) => Promise.all(agents.map((a) => a.served()));
const rollout = async (t: { admin: string }) => (await call("GET", "/v1/rollout", t.admin)).data.rollout;

describe("staged rollout", () => {
  it("goes to one connector, then a tenth of the fleet, then all of it", async () => {
    const { t, agents } = await fleet(12);
    const promoted = await call("POST", "/v1/policies/2/promote", t.admin, { soak_seconds: 0 });
    expect(promoted.data).toEqual({ version: 2, state: "rolling_out", stage: "first_agent", soak_seconds: 0 });

    // Stage 1: exactly one connector is offered version 2; the rest keep 1.
    let served = await servedVersions(agents);
    expect(served.filter((v) => v === 2)).toHaveLength(1);
    expect(served.filter((v) => v === 1)).toHaveLength(11);
    expect(await rollout(t)).toMatchObject({ version: 2, stage: "first_agent", live_agents: 12, on_version: 0, halted: false });
    // A connector that does not name itself is never part of a rollout.
    expect((await call("GET", "/v1/agent/policy/active", t.agent)).data.payload).toBeDefined();

    // It adopts the version and reports a healthy window: on to a tenth (2 of 12).
    const first = agents[served.indexOf(2)]!;
    await first.report(2);
    expect(await rollout(t)).toMatchObject({ stage: "ten_percent", on_version: 1 });
    served = await servedVersions(agents);
    expect(served.filter((v) => v === 2)).toHaveLength(2);
    expect(served[agents.indexOf(first)]).toBe(2); // the first one stays in

    // Both report under version 2: the rollout completes and 2 is the active version.
    for (const [i, v] of served.entries()) if (v === 2) await agents[i]!.report(2);
    const list = await call("GET", "/v1/policies", t.admin);
    expect(list.data).toMatchObject({ active_version: 2, candidate_version: null, rollout: null });
    expect(new Set(await servedVersions(agents))).toEqual(new Set([2]));
  });

  it("waits for the soak time before moving on", async () => {
    const { t, agents } = await fleet(3);
    await call("POST", "/v1/policies/2/promote", t.admin, { soak_seconds: 3600 });
    const served = await servedVersions(agents);
    await agents[served.indexOf(2)]!.report(2);
    expect(await rollout(t)).toMatchObject({ stage: "first_agent", on_version: 1 });
  });

  it("halts on a leak canary, stops spreading, and keeps the version where it already is", async () => {
    const { t, agents } = await fleet(5);
    await call("POST", "/v1/policies/2/promote", t.admin, { soak_seconds: 0 });
    const first = agents[(await servedVersions(agents)).indexOf(2)]!;
    await first.report(2, { leaks: 1 });

    const state = await rollout(t);
    expect(state).toMatchObject({ stage: "first_agent", halted: true });
    expect(state.halted_reason).toContain(`leak canary failed on ${first.instance} under version 2`);
    // Nobody else is offered version 2; the connector already on it is not pushed back
    // (it would refuse version 1 anyway).
    const served = await servedVersions(agents);
    expect(served.filter((v) => v === 2)).toEqual([2]);
    expect(served[agents.indexOf(first)]).toBe(2);
    // More healthy windows do not unhalt it.
    await first.report(2);
    expect((await rollout(t)).halted).toBe(true);

    // Resume starts the stage over; abort ends the rollout with version 1 still active.
    expect((await call("POST", "/v1/rollout/resume", t.admin)).data.rollout).toMatchObject({ halted: false });
    expect((await call("POST", "/v1/rollout/resume", t.admin)).status).toBe(409);
    const aborted = await call("POST", "/v1/rollout/abort", t.admin);
    expect(aborted.data).toEqual({ active_version: 1, rollout: null });
    expect(await first.served()).toBe(2);
    expect((await call("POST", "/v1/rollout/abort", t.admin)).status).toBe(409);
  });

  it("halts when the new version dead-letters clearly more than the fleet", async () => {
    const { t, agents } = await fleet(4);
    await call("POST", "/v1/policies/2/promote", t.admin, { soak_seconds: 0 });
    const first = agents[(await servedVersions(agents)).indexOf(2)]!;
    await first.report(2, { egress: 900, dlq: 100 });
    const state = await rollout(t);
    expect(state.halted).toBe(true);
    expect(state.halted_reason).toMatch(/^DLQ rate 10\.0% on pod-\d under version 2, fleet 0\.2%$/);
  });

  it("a newer version replaces a halted rollout; versions only go up", async () => {
    const { t, agents } = await fleet(2);
    await call("POST", "/v1/policies/2/promote", t.admin, { soak_seconds: 0 });
    const first = agents[(await servedVersions(agents)).indexOf(2)]!;
    await first.report(2, { leaks: 3 });
    await call("POST", "/v1/policies", t.admin, { field_rules: { rules: {} } });
    expect((await call("POST", "/v1/policies/2/promote", t.admin)).status).toBe(409);
    expect((await call("POST", "/v1/policies/1/promote", t.admin)).status).toBe(409);
    expect((await call("POST", "/v1/policies/3/promote", t.admin, { soak_seconds: 0 })).status).toBe(200);
    expect(await rollout(t)).toMatchObject({ version: 3, stage: "first_agent", halted: false });
    // Immediate promotion of the rollout's version ends it.
    expect((await call("POST", "/v1/policies/3/promote", t.admin, IMMEDIATE)).data).toEqual({ version: 3, state: "active" });
    expect(await rollout(t)).toBeNull();
    expect(new Set(await servedVersions(agents))).toEqual(new Set([3]));
  });

  it.each([[{ strategy: "yolo" }], [{ soak_seconds: -1 }], [{ soak_seconds: 1.5 }], [{ extra: 1 }], ["not json"]])(
    "refuses a malformed promotion %#",
    async (bad) => {
      const { t } = await fleet(1);
      expect((await call("POST", "/v1/policies/2/promote", t.admin, bad)).status).toBe(typeof bad === "string" ? 400 : 422);
    },
  );
});

describe("connector enrollment", () => {
  it("tells a connector token which tenant it belongs to, and nothing to an admin token", async () => {
    const t = await tenant();
    expect((await call("GET", "/v1/agent/whoami", t.agent)).data).toMatchObject({ tenant: t.id, label: "prod cluster" });
    expect((await call("GET", "/v1/agent/whoami", t.admin)).status).toBe(403);
    expect((await call("GET", "/v1/agent/whoami")).status).toBe(401);
  });

  it("accepts leak-canary counts and refuses anything else in their place", async () => {
    const t = await tenant();
    const ok = event(t.id, 0, null, { canary: { checks: 4, leaks: 0 } });
    expect((await call("POST", "/v1/agent/telemetry", t.agent, ok)).status).toBe(202);
    const agents = (await call("GET", "/v1/agents", t.admin)).data.agents;
    expect(agents[0]).toMatchObject({ canary_checks: 4, canary_leaks: 0, egress_records: 48210, dlq_records: 3 });
    for (const canary of [{ checks: 1, leaks: 0, sample: "bob@corp.example" }, { checks: "1", leaks: 0 }, "leaked"]) {
      const bad = event(t.id, 1, await sha256(ok), { canary });
      expect((await call("POST", "/v1/agent/telemetry", t.agent, bad)).status).toBe(422);
    }
  });
});

describe("tenant isolation", () => {
  it("one tenant sees nothing of another's, on every route", async () => {
    const a = await tenant("alpha");
    const b = await tenant("bravo");
    await call("POST", "/v1/policies", a.admin, { field_rules: RULES });
    await call("POST", "/v1/policies/1/promote", a.admin, IMMEDIATE);
    await call("POST", "/v1/agent/telemetry", a.agent, event(a.id, 0, null));

    // B's admin: no policies, agents, chains or tokens of A's.
    expect((await call("GET", "/v1/policies", b.admin)).data).toMatchObject({ active_version: null, policies: [] });
    expect((await call("GET", "/v1/agents", b.admin)).data.agents).toEqual([]);
    expect((await call("GET", "/v1/chains", b.admin)).data.chains).toEqual([]);
    const bTokens = (await call("GET", "/v1/tokens", b.admin)).data.tokens;
    expect(bTokens).toHaveLength(2);
    // B cannot promote A's version (B has no version 1), revoke A's tokens, or fetch A's policy.
    expect((await call("POST", "/v1/policies/1/promote", b.admin, IMMEDIATE)).status).toBe(409);
    const aAgent = (await call("GET", "/v1/tokens", a.admin)).data.tokens.find((x: any) => x.kind === "agent");
    expect((await call("POST", `/v1/tokens/${aAgent.id}/revoke`, b.admin)).status).toBe(404);
    expect((await call("GET", "/v1/agent/policy/active", b.agent)).status).toBe(404);
    // A is untouched by all of that.
    expect((await call("GET", "/v1/agent/policy/active", a.agent)).status).toBe(200);
    expect((await call("GET", "/v1/policies", a.admin)).data.active_version).toBe(1);

    // The same chain id used by two tenants stays two chains.
    await call("POST", "/v1/agent/telemetry", b.agent, event(b.id, 0, null, { policy: null }));
    expect((await call("GET", "/v1/chains", a.admin)).data.chains).toHaveLength(1);
    expect((await call("GET", "/v1/chains", b.admin)).data.chains).toHaveLength(1);
  });
});

describe("compatibility with the connector", () => {
  // The same file is verified by the Python connector's own code in
  // tests/test_control_plane_bundle.py: if either side changes the bundle
  // format or the key id, one of the two tests fails.
  // tests/test_control_contract.py keeps this file identical in shape to the
  // audit event the connector builds; here the Worker must accept it as is.
  it("accepts the audit event the connector builds", async () => {
    const fixture = (await import("./fixtures/audit-event.json?raw")).default as string;
    const created = await call("POST", "/v1/admin/tenants", "test-platform-admin-token", { id: "contract-acme", name: "Contract" });
    const agent = await call("POST", "/v1/agent-tokens", created.data.admin_token, { label: "contract" });
    const posted = await call("POST", "/v1/agent/telemetry", agent.data.token, fixture);
    expect(posted.status).toBe(202);
    expect(posted.data.head).toBe(await sha256(fixture));
  });

  it("signs the committed fixture byte for byte", async () => {
    const { signBundle, wrap } = await import("../src/crypto");
    const fixture = (await import("./fixtures/policy-bundle.json?raw")).default as string;
    const keys = (await import("./fixtures/signing-key.json")).default;
    const pkcs8 = Uint8Array.from(atob(keys.private_key_pkcs8), (c) => c.charCodeAt(0));
    const kek = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const bundle = await signBundle(
      { keyId: keys.key_id, wrappedPrivateKey: await wrap(pkcs8.buffer, kek) },
      kek,
      { tenant: "acme", version: 7, issued_at: "2026-11-11T09:00:00.000Z", field_rules: RULES },
    );
    expect(bundle).toBe(fixture);
  });
});

describe("documentation", () => {
  it("openapi.yaml lists every route the Worker serves", async () => {
    const spec = (await import("../openapi.yaml?raw")).default as string;
    const source = (await import("../src/index.ts?raw")).default as string;
    const served = [...source.matchAll(/\["(GET|POST)", \/\^(.+?)\$\/,/g)].map((m) =>
      m[2]!.replaceAll("\\/", "/").replace(/\((?:\[0-9a-f\]\{12\})\)/, "{id}").replace(/\(\[1-9\].*?\)/, "{version}").replace("(active|candidate)", "{which}").replace("([A-Za-z0-9][A-Za-z0-9._-]{0,252})", "{chain}"),
    );
    expect(served.length).toBe(22);
    for (const path of served) expect(spec, path).toContain(`  ${path}:`);
  });
});
