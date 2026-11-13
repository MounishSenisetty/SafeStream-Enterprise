// SafeStream control plane: signs and distributes redaction policies, and
// keeps what connectors report about themselves. It never receives record
// content: see validate.ts for how that is enforced on the one upload path.
//
// A caller's tenant always comes from its token, never from the request, so
// one tenant cannot name another's data.

import { consoleFetch } from "./console";
import { newTenantKey, newToken, sha256Hex, signBundle } from "./crypto";
import { delegated, type Principal } from "./principal";
import { advance, cohort, DEFAULT_SOAK_SECONDS, halt, healthProblem, liveAgents, servedVersion, STAGES, tenantState } from "./rollout";
import { auditEvent, fieldRules, Invalid, NAME, object_, string_, TENANT } from "./validate";

export interface Env {
  DB: D1Database;
  POLICIES: R2Bucket;
  AUDIT: R2Bucket;
  /** Creates tenants. Held by the operator of the control plane only. */
  PLATFORM_ADMIN_TOKEN: string;
  /** 32 random bytes, base64. Encrypts tenant signing keys at rest. */
  KEY_ENCRYPTION_KEY: string;
  /** The console's static pages (Workers static assets). */
  ASSETS?: Fetcher;
  /** Host the console is served on (e.g. app.safestreamdata.com); the API is served on every other. */
  CONSOLE_HOST?: string;
  /** Cloudflare Access team domain and the console application's audience tag. */
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
  /** Access signing keys as JSON, instead of fetching them. Tests and local runs only. */
  ACCESS_JWKS?: string;
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

function bearer(request: Request): string {
  const header = request.headers.get("authorization") ?? "";
  if (!header.startsWith("Bearer ")) throw new HttpError(401, "unauthenticated", "Bearer token required");
  return header.slice(7);
}

async function authenticate(request: Request, env: Env, kind: Principal["kind"]): Promise<Principal> {
  // A console session, already verified by console.ts (Access identity, role).
  const session = delegated.get(request);
  if (session) {
    if (session.kind !== kind) throw new HttpError(403, "forbidden", `This route needs a tenant ${kind} token`);
    return session;
  }
  const hash = await sha256Hex(bearer(request));
  const row = await env.DB.prepare(
    "SELECT tenant_id, kind, label FROM tokens WHERE hash = ? AND revoked_at IS NULL",
  )
    .bind(hash)
    .first<{ tenant_id: string; kind: Principal["kind"]; label: string }>();
  if (!row) throw new HttpError(401, "unauthenticated", "Unknown or revoked token");
  if (row.kind !== kind) throw new HttpError(403, "forbidden", `This route needs a tenant ${kind} token`);
  return { tenant: row.tenant_id, kind: row.kind, id: hash.slice(0, 12), label: row.label };
}

/** The body, read with a cap: an oversized one is refused before it is held in memory. */
async function readCapped(request: Request): Promise<Uint8Array<ArrayBuffer>> {
  const tooLarge = () => new HttpError(413, "too_large", "Request body is too large");
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (declared > MAX_BODY_BYTES) throw tooLarge();
  if (!request.body) return new Uint8Array(0);
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY_BYTES) {
      await reader.cancel();
      throw tooLarge();
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, at);
    at += chunk.byteLength;
  }
  return bytes;
}

async function body(request: Request, optional = false): Promise<{ bytes: Uint8Array<ArrayBuffer>; json: unknown }> {
  const bytes = await readCapped(request);
  if (optional && bytes.length === 0) return { bytes, json: {} };
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
  const input = object_((await body(request, true)).json, "promote", ["strategy", "soak_seconds"]);
  const strategy = input.strategy ?? "staged";
  if (strategy !== "staged" && strategy !== "immediate")
    throw new Invalid("promote.strategy: must be one of staged, immediate");
  const soak = input.soak_seconds ?? DEFAULT_SOAK_SECONDS;
  if (!Number.isSafeInteger(soak) || (soak as number) < 0 || (soak as number) > 7 * 86400)
    throw new Invalid("promote.soak_seconds: must be an integer from 0 to 604800");
  const exists = "EXISTS (SELECT 1 FROM policies WHERE tenant_id = ?2 AND version = ?1)";
  if (strategy === "immediate") {
    // Everyone at once: for an urgent fix, or a tenant with no connectors yet.
    // Ends a rollout of this version or an older one.
    const done = await env.DB.prepare(
      `UPDATE tenants
          SET active_version = ?1,
              candidate_version = CASE WHEN candidate_version <= ?1 THEN NULL ELSE candidate_version END,
              rollout_version = CASE WHEN rollout_version <= ?1 THEN NULL ELSE rollout_version END,
              rollout_stage = CASE WHEN rollout_version <= ?1 THEN NULL ELSE rollout_stage END,
              rollout_stage_started_at = CASE WHEN rollout_version <= ?1 THEN NULL ELSE rollout_stage_started_at END,
              rollout_soak_seconds = CASE WHEN rollout_version <= ?1 THEN NULL ELSE rollout_soak_seconds END,
              rollout_halted_reason = CASE WHEN rollout_version <= ?1 THEN NULL ELSE rollout_halted_reason END
        WHERE id = ?2 AND COALESCE(active_version, 0) < ?1 AND ${exists}`,
    )
      .bind(version, tenant)
      .run();
    if (!done.meta.changes)
      throw new HttpError(409, "conflict", "No such version, or it is not newer than the active policy");
    return json({ version, state: "active" });
  }
  // Staged: replaces a rollout of an older version (the usual fix for a halted one).
  const done = await env.DB.prepare(
    `UPDATE tenants
        SET rollout_version = ?1, rollout_stage = 0, rollout_stage_started_at = ?3,
            rollout_soak_seconds = ?4, rollout_halted_reason = NULL
      WHERE id = ?2 AND COALESCE(active_version, 0) < ?1 AND COALESCE(rollout_version, 0) < ?1 AND ${exists}`,
  )
    .bind(version, tenant, now(), soak)
    .run();
  if (!done.meta.changes)
    throw new HttpError(409, "conflict", "No such version, or it is not newer than the active policy and any rollout");
  return json({ version, state: "rolling_out", stage: STAGES[0], soak_seconds: soak });
}

async function rolloutReport(env: Env, tenant: string) {
  const at = new Date();
  await advance(env.DB, tenant, at);
  const { active, rollout } = await tenantState(env.DB, tenant);
  if (!rollout) return { active_version: active, rollout: null };
  const live = await liveAgents(env.DB, tenant, at);
  const members = await cohort(tenant, rollout, live);
  return {
    active_version: active,
    rollout: {
      version: rollout.version,
      stage: STAGES[rollout.stage],
      stage_started_at: rollout.stageStartedAt,
      soak_seconds: rollout.soakSeconds,
      halted: rollout.haltedReason !== null,
      halted_reason: rollout.haltedReason,
      cohort: members,
      live_agents: live.length,
      on_version: live.filter((a) => a.policy_version === rollout.version).length,
    },
  };
}

async function getRollout(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  return json(await rolloutReport(env, tenant));
}

async function abortRollout(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  // Connectors that already run the version keep it: none accepts an older one.
  const done = await env.DB.prepare(
    `UPDATE tenants SET rollout_version = NULL, rollout_stage = NULL, rollout_stage_started_at = NULL,
            rollout_soak_seconds = NULL, rollout_halted_reason = NULL
      WHERE id = ? AND rollout_version IS NOT NULL`,
  )
    .bind(tenant)
    .run();
  if (!done.meta.changes) throw new HttpError(409, "conflict", "No rollout in progress");
  return json(await rolloutReport(env, tenant));
}

async function resumeRollout(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  // The stage starts over: its soak time and every connector's report again.
  const done = await env.DB.prepare(
    "UPDATE tenants SET rollout_halted_reason = NULL, rollout_stage_started_at = ? WHERE id = ? AND rollout_halted_reason IS NOT NULL",
  )
    .bind(now(), tenant)
    .run();
  if (!done.meta.changes) throw new HttpError(409, "conflict", "No halted rollout");
  return json(await rolloutReport(env, tenant));
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
  const { rollout } = await rolloutReport(env, tenant);
  return json({ ...state, rollout, policies: policies.results });
}

async function listAgents(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const { results } = await env.DB.prepare(
    `SELECT instance, connector_version, policy_version, shadow_version, first_seen_at, last_seen_at,
            window_egress AS egress_records, window_dlq AS dlq_records,
            window_canary_checks AS canary_checks, window_canary_leaks AS canary_leaks
       FROM agents WHERE tenant_id = ? ORDER BY last_seen_at DESC LIMIT 500`,
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

/** One version: its state and its field rules, decoded from the signed bundle. */
async function policyDetail(request: Request, env: Env, versionText: string): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const version = Number(versionText);
  const row = await env.DB.prepare(
    `SELECT p.version, 'sha256:' || p.digest AS digest, p.rule_count AS rules, p.created_at,
            t.active_version, t.candidate_version, t.rollout_version, t.key_id
       FROM policies p JOIN tenants t ON t.id = p.tenant_id WHERE p.tenant_id = ? AND p.version = ?`,
  )
    .bind(tenant, version)
    .first<{ version: number; digest: string; rules: number; created_at: string; active_version: number | null; candidate_version: number | null; rollout_version: number | null; key_id: string }>();
  if (!row) throw new HttpError(404, "not_found", "No such version");
  const stored = await env.POLICIES.get(bundleKey(tenant, version));
  if (!stored) throw new HttpError(500, "internal", "Policy bundle is missing from storage");
  const bundle = (await stored.json()) as { payload: string };
  const payload = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(bundle.payload), (c) => c.charCodeAt(0)))) as {
    issued_at: string;
    field_rules: unknown;
  };
  const state =
    row.version === row.rollout_version
      ? "rolling_out"
      : row.version === row.active_version
        ? "active"
        : row.version === row.candidate_version
          ? "candidate"
          : (row.active_version ?? 0) > row.version
            ? "superseded"
            : "published";
  return json({
    version: row.version,
    state,
    digest: row.digest,
    rules: row.rules,
    key_id: row.key_id,
    created_at: row.created_at,
    issued_at: payload.issued_at,
    field_rules: payload.field_rules,
  });
}

/**
 * The fleet's shadow evaluation of the candidate, summed over the connectors
 * evaluating it now: what promoting it would change, as counts.
 */
async function shadowReport(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const state = await env.DB.prepare("SELECT active_version, candidate_version FROM tenants WHERE id = ?")
    .bind(tenant)
    .first<{ active_version: number | null; candidate_version: number | null }>();
  const candidate = state?.candidate_version ?? null;
  const since = new Date(Date.now() - 10 * 60_000).toISOString();
  const { results } = candidate
    ? await env.DB.prepare(
        `SELECT instance, policy_version, shadow_since, shadow_records, shadow_changed_records, shadow_errors,
                shadow_active, shadow_candidate
           FROM agents WHERE tenant_id = ? AND shadow_version = ? AND last_seen_at >= ? LIMIT 5000`,
      )
        .bind(tenant, candidate, since)
        .all<{ instance: string; policy_version: number | null; shadow_since: string | null; shadow_records: number | null; shadow_changed_records: number | null; shadow_errors: number | null; shadow_active: string | null; shadow_candidate: string | null }>()
    : { results: [] };
  const active: Record<string, number> = {};
  const proposed: Record<string, number> = {};
  let records = 0;
  let changed = 0;
  let errors = 0;
  for (const a of results) {
    records += a.shadow_records ?? 0;
    changed += a.shadow_changed_records ?? 0;
    errors += a.shadow_errors ?? 0;
    for (const [entity, n] of Object.entries(JSON.parse(a.shadow_active ?? "{}") as Record<string, number>))
      active[entity] = (active[entity] ?? 0) + n;
    for (const [entity, n] of Object.entries(JSON.parse(a.shadow_candidate ?? "{}") as Record<string, number>))
      proposed[entity] = (proposed[entity] ?? 0) + n;
  }
  const entities = [...new Set([...Object.keys(active), ...Object.keys(proposed)])].sort();
  return json({
    active_version: state?.active_version ?? null,
    candidate_version: candidate,
    agents: results.map((a) => ({ instance: a.instance, policy_version: a.policy_version, since: a.shadow_since, records: a.shadow_records })),
    records,
    changed_records: changed,
    errors,
    // Per entity type: redactions under the policy in force, under the
    // candidate, and the difference promoting it would make.
    entities: entities.map((entity) => ({
      entity,
      active: active[entity] ?? 0,
      candidate: proposed[entity] ?? 0,
      delta: (proposed[entity] ?? 0) - (active[entity] ?? 0),
    })),
  });
}

/**
 * Every stored event of one audit chain, in order, as NDJSON: the evidence
 * for "safestream-audit verify", with the anchored head in a header.
 */
async function exportChain(request: Request, env: Env, chainId: string): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const chain = await env.DB.prepare("SELECT head, broken, closed FROM chains WHERE tenant_id = ? AND chain_id = ?")
    .bind(tenant, chainId)
    .first<{ head: string; broken: number; closed: number }>();
  if (!chain) throw new HttpError(404, "not_found", "No such chain");
  const prefix = `tenants/${tenant}/chains/${chainId}/`;
  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const write = async () => {
    const writer = writable.getWriter();
    const newline = new TextEncoder().encode("\n");
    try {
      let cursor: string | undefined;
      do {
        // Keys are "<seq, zero-padded>-<hash prefix>.json": listing order is chain order.
        const page = await env.AUDIT.list({ prefix, cursor, limit: 1000 });
        for (const object of page.objects) {
          const stored = await env.AUDIT.get(object.key);
          if (!stored) continue;
          await writer.write(new Uint8Array(await stored.arrayBuffer()));
          await writer.write(newline);
        }
        cursor = page.truncated ? page.cursor : undefined;
      } while (cursor);
      await writer.close();
    } catch (err) {
      await writer.abort(err);
    }
  };
  void write();
  return new Response(readable, {
    headers: {
      "content-type": "application/x-ndjson",
      "content-disposition": `attachment; filename="${chainId}.ndjson"`,
      "cache-control": "no-store",
      "x-safestream-chain-head": chain.head,
      "x-safestream-chain-broken": String(chain.broken),
      "x-safestream-chain-closed": String(chain.closed),
    },
  });
}

const EMAIL = /^[^\s@]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}$/;

async function listConsoleUsers(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const { results } = await env.DB.prepare(
    "SELECT email, role, created_at FROM console_users WHERE tenant_id = ? ORDER BY email",
  )
    .bind(tenant)
    .all();
  return json({ users: results });
}

/** Give a person (their Access email) console access to this tenant, or change their role. */
async function grantConsoleUser(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const input = object_((await body(request)).json, "user", ["email", "role"]);
  const email = string_(input.email, "user.email", EMAIL).toLowerCase();
  const role = input.role ?? "viewer";
  if (role !== "viewer" && role !== "admin") throw new Invalid("user.role: must be one of viewer, admin");
  await env.DB.prepare(
    `INSERT INTO console_users (email, tenant_id, role, created_at) VALUES (?, ?, ?, ?)
     ON CONFLICT (email, tenant_id) DO UPDATE SET role = excluded.role`,
  )
    .bind(email, tenant, role, now())
    .run();
  return json({ email, role }, 201);
}

async function removeConsoleUser(request: Request, env: Env): Promise<Response> {
  const { tenant } = await authenticate(request, env, "admin");
  const input = object_((await body(request)).json, "user", ["email"]);
  const email = string_(input.email, "user.email", EMAIL).toLowerCase();
  const done = await env.DB.prepare("DELETE FROM console_users WHERE email = ? AND tenant_id = ?").bind(email, tenant).run();
  if (!done.meta.changes) throw new HttpError(404, "not_found", "No such console user");
  return json({ removed: email });
}

// ---------------------------------------------------------------------------
// agents (connectors)
// ---------------------------------------------------------------------------

async function whoami(request: Request, env: Env): Promise<Response> {
  const { tenant, id, label } = await authenticate(request, env, "agent");
  return json({ tenant, id, label });
}

/** The connector's own name, from the header it sends; null if absent or malformed. */
function instanceOf(request: Request): string | null {
  const value = request.headers.get("x-safestream-instance");
  return value && NAME.test(value) ? value : null;
}

async function agentPolicy(request: Request, env: Env, which: "active" | "candidate"): Promise<Response> {
  const { tenant } = await authenticate(request, env, "agent");
  let version: number | null;
  if (which === "active") {
    // Which version this connector gets depends on where a rollout stands.
    version = await servedVersion(env.DB, tenant, instanceOf(request), new Date());
  } else {
    const row = await env.DB.prepare("SELECT candidate_version AS version FROM tenants WHERE id = ?")
      .bind(tenant)
      .first<{ version: number | null }>();
    version = row?.version ?? null;
  }
  if (!version) throw new HttpError(404, "not_found", `No ${which} policy`);
  const row = { version };
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
      `INSERT INTO agents (tenant_id, instance, first_seen_at, last_seen_at, connector_version, policy_version, shadow_version,
                           window_reported_at, window_egress, window_dlq, window_canary_checks, window_canary_leaks,
                           shadow_since, shadow_records, shadow_changed_records, shadow_errors, shadow_active, shadow_candidate)
       VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6, ?3, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)
       ON CONFLICT (tenant_id, instance) DO UPDATE SET
         last_seen_at = ?3, connector_version = ?4, policy_version = ?5, shadow_version = ?6,
         window_reported_at = ?3, window_egress = ?7, window_dlq = ?8,
         window_canary_checks = ?9, window_canary_leaks = ?10,
         shadow_since = ?11, shadow_records = ?12, shadow_changed_records = ?13, shadow_errors = ?14,
         shadow_active = ?15, shadow_candidate = ?16`,
    ).bind(
      tenant, event.instance, at, event.connectorVersion, event.policyVersion, event.shadowVersion,
      event.records.egress, event.records.dlq, event.canary?.checks ?? null, event.canary?.leaks ?? null,
      event.shadow?.since ?? null, event.shadow?.records ?? null, event.shadow?.changedRecords ?? null,
      event.shadow?.errors ?? null,
      event.shadow ? JSON.stringify(event.shadow.active) : null,
      event.shadow ? JSON.stringify(event.shadow.candidate) : null,
    ),
  ]);
  await judgeRollout(env, tenant, event.instance);
  if (!extends_)
    // Kept as evidence, but the chain is now marked: something is missing or changed.
    throw new HttpError(409, "chain_break", "Event does not extend the recorded head of its chain");
  return json({ accepted: true, head: hash }, 202);
}

/** A new window may halt the rollout, or complete its stage. */
async function judgeRollout(env: Env, tenant: string, instance: string): Promise<void> {
  const { rollout } = await tenantState(env.DB, tenant);
  if (!rollout || rollout.haltedReason) return;
  const at = new Date();
  const fleet = await liveAgents(env.DB, tenant, at);
  const agent = fleet.find((a) => a.instance === instance);
  const problem = agent ? healthProblem(rollout, agent, fleet) : null;
  if (problem) await halt(env.DB, tenant, rollout.version, problem);
  else await advance(env.DB, tenant, at);
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
  ["GET", /^\/v1\/policies\/([1-9][0-9]{0,8})$/, policyDetail],
  ["POST", /^\/v1\/policies\/([1-9][0-9]{0,8})\/promote$/, promotePolicy],
  ["POST", /^\/v1\/policies\/candidate\/withdraw$/, withdrawCandidate],
  ["GET", /^\/v1\/rollout$/, getRollout],
  ["POST", /^\/v1\/rollout\/abort$/, abortRollout],
  ["POST", /^\/v1\/rollout\/resume$/, resumeRollout],
  ["GET", /^\/v1\/agents$/, listAgents],
  ["GET", /^\/v1\/chains$/, listChains],
  ["GET", /^\/v1\/chains\/([A-Za-z0-9][A-Za-z0-9._-]{0,252})\/events$/, exportChain],
  ["GET", /^\/v1\/shadow$/, shadowReport],
  ["GET", /^\/v1\/console-users$/, listConsoleUsers],
  ["POST", /^\/v1\/console-users$/, grantConsoleUser],
  ["POST", /^\/v1\/console-users\/remove$/, removeConsoleUser],
  ["GET", /^\/v1\/agent\/whoami$/, whoami],
  ["GET", /^\/v1\/agent\/policy\/(active|candidate)$/, (rq, env, which) => agentPolicy(rq, env, which as "active")],
  ["POST", /^\/v1\/agent\/telemetry$/, telemetry],
];

async function route(request: Request, env: Env, pathname: string): Promise<Response> {
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
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    // The console's host serves the console and nothing else; every other
    // host serves the API and never the console.
    if (env.CONSOLE_HOST && url.hostname === env.CONSOLE_HOST) {
      try {
        return await consoleFetch(request, env, (rq, pathname, principal) => {
          delegated.set(rq, principal);
          return route(rq, env, pathname);
        });
      } catch (err) {
        console.error(err);
        return json({ error: "internal", message: "Internal error" }, 500);
      }
    }
    if (url.pathname === "/healthz") return json({ ok: true });
    return route(request, env, url.pathname);
  },
} satisfies ExportedHandler<Env>;
