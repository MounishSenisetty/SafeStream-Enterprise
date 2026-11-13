// The console at app.safestreamdata.com: static pages, plus /console/api/*,
// which is the tenant-admin API of index.ts reached with a person's Access
// identity instead of a token.
//
//   person ──Access (their IdP)──▶ Worker: verify JWT ─▶ console_users ─▶ tenant + role
//                                                   └▶ the same handlers as /v1/*
//
// What a person may do follows their role: a viewer reads, an admin also
// publishes, promotes, rolls out and manages tokens and console users. Every
// change is logged (who, which tenant, which route; never a body).

import { AccessDenied, staticKeysAllowed, verifyAccessJwt } from "./access";
import type { Principal } from "./principal";

export interface ConsoleEnv {
  DB: D1Database;
  ASSETS?: Fetcher;
  CONSOLE_HOST?: string;
  ACCESS_TEAM_DOMAIN?: string;
  ACCESS_AUD?: string;
  ACCESS_JWKS?: string;
}

/** Routes of the tenant-admin API a console session may use, as /console/api/<rest>. */
const ALLOWED = /^\/v1\/(tokens|agent-tokens|policies|rollout|agents|chains|shadow|console-users)(\/|$)/;
const SELECT_TENANT = "x-safestream-tenant";
/** Sent by the console's own script on every change: a cross-site form cannot set it. */
const CSRF_HEADER = "x-safestream-console";

const SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
};

function withHeaders(response: Response, extra: Record<string, string> = {}): Response {
  const out = new Response(response.body, response);
  for (const [k, v] of Object.entries({ ...SECURITY_HEADERS, ...extra })) out.headers.set(k, v);
  return out;
}

const problem = (status: number, error: string, message: string): Response =>
  withHeaders(Response.json({ error, message }, { status }), { "cache-control": "no-store" });

interface Membership {
  tenant_id: string;
  name: string;
  role: "viewer" | "admin";
}

export type Dispatch = (request: Request, pathname: string, principal: Principal) => Promise<Response>;

export async function consoleFetch(request: Request, env: ConsoleEnv, dispatch: Dispatch): Promise<Response> {
  if (!env.ACCESS_TEAM_DOMAIN || !env.ACCESS_AUD)
    return problem(503, "not_configured", "The console is not configured on this deployment");
  if (env.ACCESS_JWKS && !staticKeysAllowed(env.CONSOLE_HOST)) {
    console.error("ACCESS_JWKS is set on a real console host; refusing to serve the console");
    return problem(503, "not_configured", "The console is misconfigured on this deployment");
  }

  let email: string;
  try {
    const token = request.headers.get("cf-access-jwt-assertion");
    if (!token) throw new AccessDenied("no Access token");
    email = await verifyAccessJwt(token, {
      teamDomain: env.ACCESS_TEAM_DOMAIN,
      audience: env.ACCESS_AUD,
      jwks: env.ACCESS_JWKS,
    });
  } catch (err) {
    if (!(err instanceof AccessDenied)) throw err;
    // Even the static pages: nothing here is for someone Access did not let in.
    return problem(403, "forbidden", `Sign in through Cloudflare Access (${err.message})`);
  }

  const { pathname } = new URL(request.url);
  if (!pathname.startsWith("/console/api/")) {
    if (request.method !== "GET" && request.method !== "HEAD") return problem(405, "method_not_allowed", "Method not allowed");
    if (!env.ASSETS) return problem(503, "not_configured", "Console assets are not deployed");
    return withHeaders(await env.ASSETS.fetch(request), { "cache-control": "no-cache" });
  }

  const { results: memberships } = await env.DB.prepare(
    `SELECT c.tenant_id, t.name, c.role FROM console_users c JOIN tenants t ON t.id = c.tenant_id
      WHERE c.email = ? ORDER BY c.tenant_id`,
  )
    .bind(email)
    .all<Membership>();
  if (memberships.length === 0)
    return problem(403, "forbidden", `${email} has no access to any tenant; ask a tenant admin to add you`);
  const wanted = request.headers.get(SELECT_TENANT);
  const current = wanted
    ? memberships.find((m) => m.tenant_id === wanted)
    : memberships.length === 1
      ? memberships[0]
      : undefined;

  const rest = pathname.slice("/console/api".length);
  if (rest === "/me") {
    return withHeaders(
      Response.json({
        email,
        tenant: current ? { id: current.tenant_id, name: current.name, role: current.role } : null,
        tenants: memberships.map((m) => ({ id: m.tenant_id, name: m.name, role: m.role })),
      }),
      { "cache-control": "no-store" },
    );
  }
  if (!current)
    return wanted
      ? problem(403, "forbidden", "You have no access to that tenant")
      : problem(400, "choose_tenant", `Choose a tenant with the ${SELECT_TENANT} header`);

  const target = `/v1${rest}`;
  if (!ALLOWED.test(target)) return problem(404, "not_found", "No such route");
  if (request.method !== "GET") {
    if (current.role !== "admin") return problem(403, "forbidden", "Your role in this tenant is viewer: read only");
    // Cross-site request forgery: Access authenticates by cookie, so a change
    // must also prove it came from the console's own script on its own origin.
    const origin = request.headers.get("origin");
    if (request.headers.get(CSRF_HEADER) !== "1" || origin !== new URL(request.url).origin)
      return problem(403, "forbidden", "Changes must come from the console itself");
    console.log(
      JSON.stringify({ event: "console_change", email, tenant: current.tenant_id, method: request.method, route: target }),
    );
  }
  const response = await dispatch(request, target, {
    tenant: current.tenant_id,
    kind: "admin",
    id: "console",
    label: email,
    role: current.role,
  });
  return withHeaders(response, { "cache-control": "no-store" });
}
