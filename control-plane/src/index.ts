// SafeStream control plane: signs and distributes redaction policies, and
// keeps what connectors report about themselves. It never receives record
// content: see validate.ts for how that is enforced on the one upload path.
//
// A caller's tenant always comes from its token, never from the request, so
// one tenant cannot name another's data.

import { newTenantKey, newToken, sha256Hex, signBundle } from "./crypto";
import { auditEvent, fieldRules, Invalid, object_, string_, TENANT } from "./validate";

export interface Env {
  DB: D1Database;
  POLICIES: R2Bucket;
  AUDIT: R2Bucket;
  /** Creates tenants. Held by the operator of the control plane only. */
  PLATFORM_ADMIN_TOKEN: string;
  /** 32 random bytes, base64. Encrypts tenant signing keys at rest. */
  KEY_ENCRYPTION_KEY: string;
}

const MAX_BODY_BYTES = 64 * 1024;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$/;

class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}): Response =>
  Response.json(body, { status, headers: { "cache-control": "no-store", ...headers } });

const now = (): string => new Date().toISOString();

interface Principal {
  tenant: string;
  kind: "admin" | "agent";
}

function bearer(request: Request): string {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "unauthenticated", "Bearer token required");
  return header.slice(7);
}

async function authenticate(request: Request, env: Env, kind: Principal["kind"]): Promise<Principal> {
  const row = await env.DB.prepare(
    "SELECT tenant_id, kind FROM tokens WHERE hash = ? AND revoked_at IS NULL",
  )
    .bind(await sha256Hex(bearer(request)))
    .first<{ tenant_id: string; kind: Principal["kind"] }>();
  if (!row) throw new HttpError(401, "unauthenticated", "Unknown or revoked token");
  if (row.kind !== kind) throw new HttpError(403, "forbidden", `This route needs a tenant ${kind} token`);
  return { tenant: row.tenant_id, kind: row.kind };
}

async function body(request: Request): Promise<{ bytes: Uint8Array<ArrayBuffer>; json: unknown }> {
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length > MAX_BODY_BYTES) throw new HttpError(413, "too_large", "Request body is too large");
  try {
    return { bytes, json: JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes)) };
  } catch {
    throw new HttpError(400, "bad_request", "Request body is not JSON");
  }
}

async function issueToken(env: Env, tenant: string, kind: Principal["kind"], label: string) {
  const token = newToken(kind);
  const hash = await sha256Hex(token);
  await env.DB.prepare("INSERT INTO tokens (hash, tenant_id, kind, label, created_at) VALUES (?, ?, ?, ?, ?)")
    .bind(hash, tenant, kind, label, now())
    .run();
  // The id is how a token is named afterwards (to revoke it); it cannot be used as one.
  return { id: hash.slice(0, 12), token };
}

// ---------------------------------------------------------------------------
// platform admin
// ---------------------------------------------------------------------------

async function createTenant(request: Request, env: Env): Promise<Response> {
  // Hash both sides so the comparison takes the same time whatever the input.
  const [given, expected] = await Promise.all([sha256Hex(bearer(request)), sha256Hex(env.PLATFORM_ADMIN_TOKEN)]);
  if (!env.PLATFORM_ADMIN_TOKEN || given !== expected)
    throw new HttpError(403, "forbidden", "Platform admin token required");
  const input = object_((await body(request)).json, "tenant", ["id", "name"]);
  const id = string_(input.id, "tenant.id", TENANT);
  const name = string_(input.name, "tenant.name", LABEL);
  const key = await newTenantKey(env.KEY_ENCRYPTION_KEY);
  try {
    await env.DB.prepare(
      "INSERT INTO tenants (id, name, created_at, key_id, public_key, wrapped_private_key) VALUES (?, ?, ?, ?, ?, ?)",
    )
      .bind(id, name, now(), key.keyId, key.publicKey, key.wrappedPrivateKey)
      .run();
  } catch {
    throw new HttpError(409, "conflict", "A tenant with this id already exists");
  }
  const admin = await issueToken(env, id, "admin", "initial admin");
  // The only time the admin token is shown.
  return json({ tenant: id, admin_token: admin.token, key_id: key.keyId, public_key: key.publicKey }, 201);
}

// ---------------------------------------------------------------------------
// tenant admin
// ---------------------------------------------------------------------------

async function createAgentToken(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const input = object_((await body(request)).json, "token", ["label"]);
  const label = string_(input.label, "token.label", LABEL);
  const tenantRow = await env.DB.prepare("SELECT key_id, public_key FROM tenants WHERE id = ?")
    .bind(tenant)
    .first<{ key_id: string; public_key: string }>();
  const issued = await issueToken(env, tenant, "agent", label);
  // Everything a connector deployment needs: its token and the key to trust.
  return json({ ...issued, label, tenant, key_id: tenantRow!.key_id, public_key: tenantRow!.public_key }, 201);
}

async function listTokens(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const { results } = await env.DB.prepare(
    "SELECT substr(hash, 1, 12) AS id, kind, label, created_at, revoked_at FROM tokens WHERE tenant_id = ? ORDER BY created_at",
  )
    .bind(tenant)
    .all();
  return json({ tokens: results });
}

async function revokeToken(request: Request, env: Env, id: string): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const done = await env.DB.prepare(
    "UPDATE tokens SET revoked_at = ? WHERE tenant_id = ? AND substr(hash, 1, 12) = ? AND revoked_at IS NULL",
  )
    .bind(now(), tenant, id)
    .run();
  if (!done.meta.changes) throw new HttpError(404, "not_found", "No such active token");
  return json({ revoked: id });
}

const bundleKey = (tenant: string, version: number): string => `tenants/${tenant}/policies/${version}.json`;

async function publishPolicy(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const input = object_((await body(request)).json, "policy", ["field_rules"]);
  const { ruleCount } = fieldRules(input.field_rules);
  const row = await env.DB.prepare(
    `SELECT key_id, wrapped_private_key,
            (SELECT COALESCE(MAX(version), 0) FROM policies WHERE tenant_id = tenants.id) AS latest
       FROM tenants WHERE id = ?`,
  )
    .bind(tenant)
    .first<{ key_id: string; wrapped_private_key: string; latest: number }>();
  // Versions only ever go up: a connector refuses anything not newer.
  const version = row!.latest + 1;
  const bundle = await signBundle(
    { keyId: row!.key_id, wrappedPrivateKey: row!.wrapped_private_key },
    env.KEY_ENCRYPTION_KEY,
    { tenant, version, issued_at: now(), field_rules: input.field_rules },
  );
  const digest = await sha256Hex(bundle);
  await env.POLICIES.put(bundleKey(tenant, version), bundle);
  try {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO policies (tenant_id, version, digest, rule_count, created_at) VALUES (?, ?, ?, ?, ?)",
      ).bind(tenant, version, digest, ruleCount, now()),
      // A new policy starts as the candidate: connectors evaluate it in shadow.
      env.DB.prepare("UPDATE tenants SET candidate_version = ? WHERE id = ?").bind(version, tenant),
    ]);
  } catch {
    throw new HttpError(409, "conflict", "Another policy was published at the same time; try again");
  }
  return json({ version, state: "candidate", key_id: row!.key_id, digest: `sha256:${digest}`, rules: ruleCount }, 201);
}

async function promotePolicy(request: Request, env: Env, versionText: string): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const version = Number(versionText);
  const done = await env.DB.prepare(
    `UPDATE tenants
        SET active_version = ?1,
            candidate_version = CASE WHEN candidate_version <= ?1 THEN NULL ELSE candidate_version END
      WHERE id = ?2
        AND COALESCE(active_version, 0) < ?1
        AND EXISTS (SELECT 1 FROM policies WHERE tenant_id = ?2 AND version = ?1)`,
  )
    .bind(version, tenant)
    .run();
  if (!done.meta.changes)
    throw new HttpError(409, "conflict", "No such version, or it is not newer than the active policy");
  return json({ version, state: "active" });
}

async function withdrawCandidate(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  await env.DB.prepare("UPDATE tenants SET candidate_version = NULL WHERE id = ?").bind(tenant).run();
  return json({ candidate: null });
}

async function listPolicies(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const [state, policies] = await Promise.all([
    env.DB.prepare("SELECT active_version, candidate_version FROM tenants WHERE id = ?").bind(tenant).first(),
    env.DB.prepare(
      "SELECT version, 'sha256:' || digest AS digest, rule_count AS rules, created_at FROM policies WHERE tenant_id = ? ORDER BY version DESC LIMIT 100",
    )
      .bind(tenant)
      .all(),
  ]);
  return json({ ...state, policies: policies.results });
}

async function listAgents(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const { results } = await env.DB.prepare(
    "SELECT instance, connector_version, policy_version, shadow_version, first_seen_at, last_seen_at FROM agents WHERE tenant_id = ? ORDER BY last_seen_at DESC LIMIT 500",
  )
    .bind(tenant)
    .all();
  return json({ agents: results });
}

async function listChains(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const { results } = await env.DB.prepare(
    "SELECT chain_id AS chain, instance, first_seq, next_seq - first_seq AS events, head, closed, broken, updated_at FROM chains WHERE tenant_id = ? ORDER BY updated_at DESC LIMIT 500",
  )
    .bind(tenant)
    .all();
  return json({ chains: results });
}

// ---------------------------------------------------------------------------
// agents (connectors)
// ---------------------------------------------------------------------------

async function agentPolicy(request: Request, env: Env, which: "active" | "candidate"): Promise<Response> {
  const { tenant } = await authenticate(request, env, "agent");
  const row = await env.DB.prepare(`SELECT ${which}_version AS version FROM tenants WHERE id = ?`)
    .bind(tenant)
    .first<{ version: number | null }>();
  if (!row?.version) throw new HttpError(404, "not_found", `No ${which} policy`);
  // A version's bundle never changes, so the version is the validator.
  const etag = `"${tenant}-${row.version}"`;
  if (request.headers.get("if-none-match") === etag) return new Response(null, { status: 304, headers: { etag } });
  const stored = await env.POLICIES.get(bundleKey(tenant, row.version));
  if (!stored) throw new HttpError(500, "internal", "Policy bundle is missing from storage");
  // Authenticated, so "private": only this caller may reuse it.
  return new Response(stored.body, {
    headers: { "content-type": "application/json", etag, "cache-control": "private, no-cache" },
  });
}

async function telemetry(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "agent");
  const { bytes, json: parsed } = await body(request);
  const event = auditEvent(parsed, tenant);
  // The chain is over the bytes the connector published, so hash them as sent.
  const hash = `sha256:${await sha256Hex(bytes)}`;
  const at = now();

  const chain = await env.DB.prepare(
    "SELECT next_seq, head, broken FROM chains WHERE tenant_id = ? AND chain_id = ?",
  )
    .bind(tenant, event.chain.id)
    .first<{ next_seq: number; head: string; broken: number }>();
  // A retry of the event already at the head is fine; say so and change nothing.
  if (chain && event.chain.seq === chain.next_seq - 1 && hash === chain.head)
    return json({ accepted: true, duplicate: true, head: chain.head });
  // The first event seen for a chain is taken as its start (a connector may be
  // connected mid-run). After that every event must extend the recorded head.
  const extends_ = !chain || (event.chain.seq === chain.next_seq && event.chain.prev === chain.head);

  await env.AUDIT.put(
    `tenants/${tenant}/chains/${event.chain.id}/${String(event.chain.seq).padStart(10, "0")}-${hash.slice(7, 19)}.json`,
    bytes,
  );
  const closed = event.final ? 1 : 0;
  let chainUpdate: D1PreparedStatement;
  if (!chain)
    chainUpdate = env.DB.prepare(
      "INSERT INTO chains (tenant_id, chain_id, instance, first_seq, next_seq, head, closed, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    ).bind(tenant, event.chain.id, event.instance, event.chain.seq, event.chain.seq + 1, hash, closed, at);
  else if (extends_)
    chainUpdate = env.DB.prepare(
      "UPDATE chains SET next_seq = ?, head = ?, closed = ?, updated_at = ? WHERE tenant_id = ? AND chain_id = ?",
    ).bind(event.chain.seq + 1, hash, closed, at, tenant, event.chain.id);
  else
    chainUpdate = env.DB.prepare(
      "UPDATE chains SET broken = 1, updated_at = ? WHERE tenant_id = ? AND chain_id = ?",
    ).bind(at, tenant, event.chain.id);
  await env.DB.batch([
    chainUpdate,
    env.DB.prepare(
      `INSERT INTO agents (tenant_id, instance, first_seen_at, last_seen_at, connector_version, policy_version, shadow_version)
       VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6)
       ON CONFLICT (tenant_id, instance) DO UPDATE SET
         last_seen_at = ?3, connector_version = ?4, policy_version = ?5, shadow_version = ?6`,
    ).bind(tenant, event.instance, at, event.connectorVersion, event.policyVersion, event.shadowVersion),
  ]);
  if (!extends_)
    // Kept as evidence, but the chain is now marked: something is missing or changed.
    throw new HttpError(409, "chain_break", "Event does not extend the recorded head of its chain");
  return json({ accepted: true, head: hash }, 202);
}

// ---------------------------------------------------------------------------
// routing
// ---------------------------------------------------------------------------

type Handler = (request: Request, env: Env, ...params: string[]) => Promise<Response>;

const routes: [method: string, pattern: RegExp, handler: Handler][] = [
  ["POST", /^\/v1\/admin\/tenants$/, createTenant],
  ["POST", /^\/v1\/agent-tokens$/, createAgentToken],
  ["GET", /^\/v1\/tokens$/, listTokens],
  ["POST", /^\/v1\/tokens\/([0-9a-f]{12})\/revoke$/, revokeToken],
  ["POST", /^\/v1\/policies$/, publishPolicy],
  ["GET", /^\/v1\/policies$/, listPolicies],
  ["POST", /^\/v1\/policies\/([1-9][0-9]{0,8})\/promote$/, promotePolicy],
  ["POST", /^\/v1\/policies\/candidate\/withdraw$/, withdrawCandidate],
  ["GET", /^\/v1\/agents$/, listAgents],
  ["GET", /^\/v1\/chains$/, listChains],
  ["GET", /^\/v1\/agent\/policy\/(active|candidate)$/, (rq, env, which) => agentPolicy(rq, env, which as "active")],
  ["POST", /^\/v1\/agent\/telemetry$/, telemetry],
];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { pathname } = new URL(request.url);
    if (pathname === "/healthz") return json({ ok: true });
    try {
      let pathMatched = false;
      for (const [method, pattern, handler] of routes) {
        const match = pattern.exec(pathname);
        if (!match) continue;
        pathMatched = true;
        if (method === request.method) return await handler(request, env, ...match.slice(1));
      }
      throw pathMatched
        ? new HttpError(405, "method_not_allowed", "Method not allowed")
        : new HttpError(404, "not_found", "No such route");
    } catch (err) {
      if (err instanceof HttpError) return json({ error: err.code, message: err.message }, err.status);
      if (err instanceof Invalid) return json({ error: "invalid", message: err.message }, 422);
      // Never echo an unexpected error to the caller; it is in the Worker's logs.
      console.error(err);
      return json({ error: "internal", message: "Internal error" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;
