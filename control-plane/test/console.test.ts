import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const API = "https://api.test";
const APP = "https://app.test";
const TEAM = "https://test-team.cloudflareaccess.com";

const b64url = (bytes: Uint8Array | string): string =>
  btoa(typeof bytes === "string" ? bytes : String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

/** An Access token as Cloudflare Access would send it, signed with the test key. */
async function accessJwt(email: string, claims: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  const jwk = JSON.parse(env.TEST_ACCESS_PRIVATE_JWK);
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: "RS256", kid: "test-key-1", typ: "JWT", ...header }));
  const body = b64url(
    JSON.stringify({ aud: ["test-console-aud"], iss: TEAM, email, iat: now, nbf: now, exp: now + 3600, type: "app", ...claims }),
  );
  const sig = new Uint8Array(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${head}.${body}`)));
  return `${head}.${body}.${b64url(sig)}`;
}

async function call(base: string, method: string, path: string, opts: { token?: string; jwt?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.jwt) headers["cf-access-jwt-assertion"] = opts.jwt;
  const response = await SELF.fetch(base + path, {
    method,
    headers,
    body: opts.body === undefined ? undefined : typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body),
  });
  const text = await response.text();
  let data: any = text;
  try {
    data = JSON.parse(text);
  } catch {}
  return { status: response.status, data, text, headers: response.headers };
}

/** A change from the console's own page: same-origin and with its marker header. */
const FROM_PAGE = { origin: APP, "x-safestream-console": "1", "content-type": "application/json" };

let counter = 0;
async function tenant(prefix = "con") {
  const id = `${prefix}-${++counter}-${crypto.randomUUID().slice(0, 6)}`;
  const created = await call(API, "POST", "/v1/admin/tenants", { token: "test-platform-admin-token", body: { id, name: `Tenant ${id}` } });
  expect(created.status).toBe(201);
  const agent = await call(API, "POST", "/v1/agent-tokens", { token: created.data.admin_token, body: { label: "cluster" } });
  return { id, admin: created.data.admin_token as string, agent: agent.data.token as string, keyId: created.data.key_id as string };
}

async function member(t: { admin: string }, email: string, role: "viewer" | "admin") {
  const r = await call(API, "POST", "/v1/console-users", { token: t.admin, body: { email, role } });
  expect(r.status).toBe(201);
  return accessJwt(email);
}

const sha256 = async (bytes: Uint8Array | string) =>
  "sha256:" +
  [...new Uint8Array(await crypto.subtle.digest("SHA-256", typeof bytes === "string" ? new TextEncoder().encode(bytes) : bytes))]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

function event(tenantId: string, keyId: string, instance: string, seq: number, prev: string | null, extra: Record<string, unknown> = {}) {
  return JSON.stringify({
    schema: "safestream.audit/v2",
    connector_version: "0.3.0",
    instance,
    group_id: "safestream-redactor",
    topics: { ingress: "ingress-logs", egress: "egress-logs-clean", dlq: "ingress-logs-dlq" },
    delivery: "exactly_once",
    redaction_mode: "pseudonymize",
    field_rules: { count: 68, fingerprint: "sha256:" + "ab".repeat(32) },
    policy: { tenant: tenantId, version: 1, key_id: keyId },
    shadow: null,
    chain: { id: `${instance}-chain`, seq, prev },
    window: { start: "2026-11-11T09:00:00.000+00:00", end: "2026-11-11T09:01:00.000+00:00", final: false },
    records: { egress: 1000, dlq: 1 },
    redactions: { email: 900 },
    batches: 10,
    transaction_aborts: 0,
    canary: { checks: 2, leaks: 0 },
    ...extra,
  });
}

describe("Access", () => {
  it("lets nobody in without a valid Access token, not even to the static pages", async () => {
    const t = await tenant();
    const good = await member(t, "ana@acme.example", "admin");
    expect((await call(APP, "GET", "/console/api/me", { jwt: good })).status).toBe(200);
    expect((await call(APP, "GET", "/")).status).toBe(403);
    expect((await call(APP, "GET", "/console/api/me")).status).toBe(403);

    const refused = [
      await accessJwt("ana@acme.example", { aud: ["another-app"] }),
      await accessJwt("ana@acme.example", { iss: "https://evil.cloudflareaccess.com" }),
      await accessJwt("ana@acme.example", { exp: Math.floor(Date.now() / 1000) - 3600 }),
      await accessJwt("ana@acme.example", { nbf: Math.floor(Date.now() / 1000) + 3600 }),
      await accessJwt("ana@acme.example", { email: undefined }),
      await accessJwt("ana@acme.example", {}, { kid: "unknown-key" }),
      await accessJwt("ana@acme.example", {}, { alg: "none" }),
      // Payload swapped after signing: the signature no longer matches.
      good.split(".")[0] + "." + b64url(JSON.stringify({ aud: ["test-console-aud"], iss: TEAM, email: "mallory@evil.example", exp: 9e9 })) + "." + good.split(".")[2],
      "not-a-jwt",
    ];
    for (const jwt of refused) {
      const r = await call(APP, "GET", "/console/api/me", { jwt });
      expect(r.status, jwt.slice(0, 40)).toBe(403);
    }
  });

  it("a person Access lets in sees nothing until a tenant admin grants them a role", async () => {
    const stranger = await accessJwt("someone@elsewhere.example");
    const r = await call(APP, "GET", "/console/api/agents", { jwt: stranger });
    expect(r.status).toBe(403);
    expect(r.data.message).toContain("no access to any tenant");
  });

  it("serves the pages with a strict content security policy", async () => {
    const t = await tenant();
    const jwt = await member(t, "page@acme.example", "viewer");
    const page = await call(APP, "GET", "/", { jwt });
    expect(page.status).toBe(200);
    expect(page.text).toContain('<script type="module" src="/console.js">');
    const csp = page.headers.get("content-security-policy")!;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(page.headers.get("x-frame-options")).toBe("DENY");
    expect((await call(APP, "GET", "/console.js", { jwt })).text).toContain("textContent");
  });
});

describe("hosts", () => {
  it("the API host never serves the console, and the console host never serves the token API", async () => {
    const t = await tenant();
    const jwt = await member(t, "host@acme.example", "admin");
    expect((await call(API, "GET", "/console/api/me", { jwt })).status).toBe(404);
    expect((await call(API, "GET", "/", { jwt })).status).toBe(404);
    // A tenant token is worthless on the console host: only an Access identity counts there.
    expect((await call(APP, "GET", "/v1/agents", { token: t.admin })).status).toBe(403);
  });

  it("a console session reaches only tenant-admin routes", async () => {
    const t = await tenant();
    const jwt = await member(t, "routes@acme.example", "admin");
    for (const path of ["/agent/policy/active", "/agent/whoami", "/admin/tenants"]) {
      expect((await call(APP, "GET", `/console/api${path}`, { jwt })).status, path).toBe(404);
    }
    const telemetry = await call(APP, "POST", "/console/api/agent/telemetry", { jwt, headers: FROM_PAGE, body: event(t.id, t.keyId, "pod-a", 0, null) });
    expect(telemetry.status).toBe(404);
  });
});

describe("roles and changes", () => {
  it("a viewer reads; an admin also publishes, rolls out and manages access", async () => {
    const t = await tenant();
    const viewer = await member(t, "viv@acme.example", "viewer");
    const admin = await member(t, "ada@acme.example", "admin");

    expect((await call(APP, "GET", "/console/api/me", { jwt: viewer })).data).toMatchObject({
      email: "viv@acme.example",
      tenant: { id: t.id, role: "viewer" },
    });
    expect((await call(APP, "GET", "/console/api/policies", { jwt: viewer })).status).toBe(200);
    for (const [path, body] of [
      ["/policies", { field_rules: { rules: {} } }],
      ["/agent-tokens", { label: "x" }],
      ["/console-users", { email: "viv@acme.example", role: "admin" }],
    ] as const) {
      const r = await call(APP, "POST", `/console/api${path}`, { jwt: viewer, headers: FROM_PAGE, body });
      expect(r.status, path).toBe(403);
    }

    const published = await call(APP, "POST", "/console/api/policies", { jwt: admin, headers: FROM_PAGE, body: { field_rules: { rules: { "*member_id*": "id_number" } } } });
    expect(published.status).toBe(201);
    // The same signed version the token API sees.
    expect((await call(API, "GET", "/v1/policies", { token: t.admin })).data.candidate_version).toBe(published.data.version);
    const promoted = await call(APP, "POST", `/console/api/policies/${published.data.version}/promote`, { jwt: admin, headers: FROM_PAGE, body: { strategy: "immediate" } });
    expect(promoted.data).toEqual({ version: 1, state: "active" });
  });

  it("refuses changes that do not come from the console's own page", async () => {
    const t = await tenant();
    const admin = await member(t, "csrf@acme.example", "admin");
    const body = { field_rules: { rules: {} } };
    for (const headers of [
      { "content-type": "application/json" }, // a cross-site form or fetch with the Access cookie
      { ...FROM_PAGE, origin: "https://evil.example" },
      { ...FROM_PAGE, "x-safestream-console": "0" },
      { "x-safestream-console": "1", "content-type": "application/json" }, // no Origin
    ] as Record<string, string>[]) {
      const r = await call(APP, "POST", "/console/api/policies", { jwt: admin, headers, body });
      expect(r.status, JSON.stringify(headers)).toBe(403);
    }
    expect((await call(API, "GET", "/v1/policies", { token: t.admin })).data.policies).toEqual([]);
  });

  it("keeps tenants apart, and lets a member of several choose", async () => {
    const a = await tenant("alpha");
    const b = await tenant("bravo");
    const onlyA = await member(a, "solo@acme.example", "admin");
    const r = await call(APP, "GET", "/console/api/agents", { jwt: onlyA, headers: { "x-safestream-tenant": b.id } });
    expect(r.status).toBe(403);

    await call(API, "POST", "/v1/console-users", { token: a.admin, body: { email: "both@acme.example", role: "viewer" } });
    await call(API, "POST", "/v1/console-users", { token: b.admin, body: { email: "both@acme.example", role: "admin" } });
    const both = await accessJwt("Both@Acme.Example"); // emails compare case-insensitively
    const me = await call(APP, "GET", "/console/api/me", { jwt: both });
    expect(me.data.tenant).toBeNull();
    expect(me.data.tenants.map((x: any) => [x.id, x.role]).sort()).toEqual([[a.id, "viewer"], [b.id, "admin"]].sort());
    expect((await call(APP, "GET", "/console/api/agents", { jwt: both })).status).toBe(400);
    // Admin in B, viewer in A: the role follows the chosen tenant.
    const inA = await call(APP, "POST", "/console/api/agent-tokens", { jwt: both, headers: { ...FROM_PAGE, "x-safestream-tenant": a.id }, body: { label: "x" } });
    expect(inA.status).toBe(403);
    const inB = await call(APP, "POST", "/console/api/agent-tokens", { jwt: both, headers: { ...FROM_PAGE, "x-safestream-tenant": b.id }, body: { label: "x" } });
    expect(inB.status).toBe(201);
    expect(inB.data.tenant).toBe(b.id);
  });

  it("console users are managed per tenant, and removal takes effect at once", async () => {
    const t = await tenant();
    const jwt = await member(t, "gone@acme.example", "admin");
    expect((await call(API, "GET", "/v1/console-users", { token: t.admin })).data.users).toMatchObject([{ email: "gone@acme.example", role: "admin" }]);
    for (const bad of [{ email: "not-an-email", role: "admin" }, { email: "x@acme.example", role: "owner" }, { email: "x@acme.example", extra: 1 }])
      expect((await call(API, "POST", "/v1/console-users", { token: t.admin, body: bad })).status).toBe(422);
    expect((await call(API, "POST", "/v1/console-users/remove", { token: t.admin, body: { email: "GONE@acme.example" } })).status).toBe(200);
    expect((await call(APP, "GET", "/console/api/agents", { jwt })).status).toBe(403);
    expect((await call(API, "POST", "/v1/console-users/remove", { token: t.admin, body: { email: "gone@acme.example" } })).status).toBe(404);
  });
});

describe("what the console shows", () => {
  it("sums the fleet's shadow evaluation into what promoting the candidate would change", async () => {
    const t = await tenant();
    await call(API, "POST", "/v1/policies", { token: t.admin, body: { field_rules: { rules: {} } } });
    await call(API, "POST", "/v1/policies/1/promote", { token: t.admin, body: { strategy: "immediate" } });
    await call(API, "POST", "/v1/policies", { token: t.admin, body: { field_rules: { rules: { "*member_id*": "id_number" } } } });
    const shadow = (records: number, person: number) => ({
      candidate: { tenant: t.id, version: 2, key_id: t.keyId },
      since: "2026-11-11T09:00:00+00:00",
      records,
      changed_records: records / 2,
      errors: 0,
      redactions: { active: { email: records }, candidate: { email: records, id_number: person } },
    });
    for (const [pod, records, ids] of [["pod-a", 100, 40], ["pod-b", 300, 60]] as const) {
      const r = await call(API, "POST", "/v1/agent/telemetry", { token: t.agent, body: event(t.id, t.keyId, pod, 0, null, { shadow: shadow(records, ids) }) });
      expect(r.status).toBe(202);
    }
    const jwt = await member(t, "shadow@acme.example", "viewer");
    const report = (await call(APP, "GET", "/console/api/shadow", { jwt })).data;
    expect(report).toMatchObject({ active_version: 1, candidate_version: 2, records: 400, changed_records: 200, errors: 0 });
    expect(report.agents).toHaveLength(2);
    expect(report.entities).toEqual([
      { entity: "email", active: 400, candidate: 400, delta: 0 },
      { entity: "id_number", active: 0, candidate: 100, delta: 100 },
    ]);
  });

  it("shows a version's rules, decoded from the bundle the connectors verify", async () => {
    const t = await tenant();
    const rules = { mode: "extend", rules: { "*member_id*": "id_number" }, disable: ["*ip*"] };
    await call(API, "POST", "/v1/policies", { token: t.admin, body: { field_rules: rules } });
    const jwt = await member(t, "rules@acme.example", "viewer");
    const detail = await call(APP, "GET", "/console/api/policies/1", { jwt });
    expect(detail.data).toMatchObject({ version: 1, state: "candidate", rules: 1, key_id: t.keyId, field_rules: rules });
    const bundle = await call(API, "GET", "/v1/agent/policy/candidate", { token: t.agent });
    expect(detail.data.digest).toBe(await sha256(bundle.text));
    expect((await call(APP, "GET", "/console/api/policies/9", { jwt })).status).toBe(404);
  });

  it("exports a chain's events byte for byte, with the anchored head", async () => {
    const t = await tenant();
    const sent: string[] = [];
    let prev: string | null = null;
    for (let seq = 0; seq < 3; seq++) {
      const e = event(t.id, t.keyId, "pod-x", seq, prev, seq === 2 ? { window: { start: "2026-11-11T09:02:00.000+00:00", end: "2026-11-11T09:03:00.000+00:00", final: true } } : {});
      expect((await call(API, "POST", "/v1/agent/telemetry", { token: t.agent, body: e })).status).toBe(202);
      sent.push(e);
      prev = await sha256(e);
    }
    const jwt = await member(t, "audit@acme.example", "viewer");
    const exported = await call(APP, "GET", "/console/api/chains/pod-x-chain/events", { jwt });
    expect(exported.status).toBe(200);
    expect(exported.headers.get("content-type")).toBe("application/x-ndjson");
    expect(exported.text).toBe(sent.join("\n") + "\n");
    expect(exported.headers.get("x-safestream-chain-head")).toBe(prev);
    expect(exported.headers.get("x-safestream-chain-closed")).toBe("1");
    // Another tenant's admin cannot name this chain.
    const other = await tenant();
    expect((await call(API, "GET", "/v1/chains/pod-x-chain/events", { token: other.admin })).status).toBe(404);
  });
});

describe("hardening", () => {
  it("refuses an oversized body before holding it, even one streamed without a length", async () => {
    const t = await tenant();
    const chunk = new TextEncoder().encode("x".repeat(16 * 1024));
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (sent++ < 64) controller.enqueue(chunk); // 1 MiB in total, never announced
        else controller.close();
      },
    });
    const r = await SELF.fetch(API + "/v1/policies", {
      method: "POST",
      headers: { authorization: `Bearer ${t.admin}` },
      body: stream,
      // @ts-expect-error workerd's fetch takes duplex for a streamed request body
      duplex: "half",
    });
    expect(r.status).toBe(413);
    expect(sent).toBeLessThan(64); // stopped reading once over the cap
  });

  it("fetches Access's keys at most once a minute, however many tokens name an unknown key", async () => {
    const { verifyAccessJwt } = await import("../src/access");
    const realFetch = globalThis.fetch;
    let fetches = 0;
    globalThis.fetch = (async () => {
      fetches += 1;
      return Response.json({ keys: JSON.parse(env.ACCESS_JWKS).keys });
    }) as typeof fetch;
    try {
      const config = { teamDomain: "test-team.cloudflareaccess.com", audience: "test-console-aud" };
      for (let i = 0; i < 5; i++) {
        const token = await accessJwt("x@acme.example", {}, { kid: `rotated-${i}` });
        await expect(verifyAccessJwt(token, config)).rejects.toThrow("unknown key");
      }
      expect(fetches).toBe(1);
      expect(await verifyAccessJwt(await accessJwt("x@acme.example"), config)).toBe("x@acme.example");
      expect(fetches).toBe(1);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it("never trusts static test keys on a real console host", async () => {
    const { consoleFetch } = await import("../src/console");
    const { staticKeysAllowed } = await import("../src/access");
    expect(staticKeysAllowed("app.safestreamdata.com")).toBe(false);
    expect(staticKeysAllowed("localhost")).toBe(true);
    expect(staticKeysAllowed("app.test")).toBe(true);
    const r = await consoleFetch(
      new Request("https://app.safestreamdata.com/console/api/me", { headers: { "cf-access-jwt-assertion": await accessJwt("x@acme.example") } }),
      { DB: env.DB, CONSOLE_HOST: "app.safestreamdata.com", ACCESS_TEAM_DOMAIN: "test-team.cloudflareaccess.com", ACCESS_AUD: "test-console-aud", ACCESS_JWKS: env.ACCESS_JWKS },
      async () => new Response("dispatched"),
    );
    expect(r.status).toBe(503);
  });
});
