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

    expect((await call("POST", "/v1/policies/1/promote", t.admin)).data).toEqual({ version: 1, state: "active" });
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

    await call("POST", "/v1/policies/2/promote", t.admin);
    // Rollback and unknown versions are refused.
    expect((await call("POST", "/v1/policies/1/promote", t.admin)).status).toBe(409);
    expect((await call("POST", "/v1/policies/2/promote", t.admin)).status).toBe(409);
    expect((await call("POST", "/v1/policies/9/promote", t.admin)).status).toBe(409);
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

describe("tenant isolation", () => {
  it("one tenant sees nothing of another's, on every route", async () => {
    const a = await tenant("alpha");
    const b = await tenant("bravo");
    await call("POST", "/v1/policies", a.admin, { field_rules: RULES });
    await call("POST", "/v1/policies/1/promote", a.admin);
    await call("POST", "/v1/agent/telemetry", a.agent, event(a.id, 0, null));

    // B's admin: no policies, agents, chains or tokens of A's.
    expect((await call("GET", "/v1/policies", b.admin)).data).toMatchObject({ active_version: null, policies: [] });
    expect((await call("GET", "/v1/agents", b.admin)).data.agents).toEqual([]);
    expect((await call("GET", "/v1/chains", b.admin)).data.chains).toEqual([]);
    const bTokens = (await call("GET", "/v1/tokens", b.admin)).data.tokens;
    expect(bTokens).toHaveLength(2);
    // B cannot promote A's version (B has no version 1), revoke A's tokens, or fetch A's policy.
    expect((await call("POST", "/v1/policies/1/promote", b.admin)).status).toBe(409);
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
      m[2]!.replaceAll("\\/", "/").replace(/\((?:\[0-9a-f\]\{12\})\)/, "{id}").replace(/\(\[1-9\].*?\)/, "{version}").replace("(active|candidate)", "{which}"),
    );
    expect(served.length).toBe(12);
    for (const path of served) expect(spec, path).toContain(`  ${path}:`);
  });
});
