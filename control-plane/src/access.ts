// Cloudflare Access in front of the console.
//
// Access authenticates the person (against each design partner's own identity
// provider) and sends the request on with a signed JWT in the
// Cf-Access-Jwt-Assertion header. The Worker does not take Access's word for
// it: it checks that JWT itself, signature (RS256, keys from the team's certs
// endpoint), audience (this Access application only), issuer and lifetime.
// Without a valid JWT nothing is served, so a misconfigured or bypassed Access
// fails closed instead of open.

export interface AccessConfig {
  /** e.g. "safestream.cloudflareaccess.com" */
  teamDomain: string;
  /** The Access application's audience tag. */
  audience: string;
  /** Keys as JSON ({"keys": [...]}) instead of fetching them: tests and local runs only. */
  jwks?: string;
}

export class AccessDenied extends Error {}

interface Jwk extends JsonWebKey {
  kid?: string;
}

const CLOCK_SKEW_S = 60;
const KEYS_TTL_MS = 60 * 60 * 1000;
let cachedKeys: { url: string; at: number; keys: Jwk[] } | null = null;

const b64urlBytes = (text: string): Uint8Array<ArrayBuffer> =>
  Uint8Array.from(atob(text.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((text.length + 3) % 4)), (c) =>
    c.charCodeAt(0),
  );

function b64urlJson(text: string): Record<string, unknown> {
  try {
    const value: unknown = JSON.parse(new TextDecoder().decode(b64urlBytes(text)));
    if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error();
    return value as Record<string, unknown>;
  } catch {
    throw new AccessDenied("malformed token");
  }
}

async function keys(config: AccessConfig, refresh: boolean): Promise<Jwk[]> {
  if (config.jwks) return (JSON.parse(config.jwks) as { keys: Jwk[] }).keys;
  const url = `https://${config.teamDomain}/cdn-cgi/access/certs`;
  if (!refresh && cachedKeys && cachedKeys.url === url && Date.now() - cachedKeys.at < KEYS_TTL_MS) return cachedKeys.keys;
  const response = await fetch(url, { headers: { accept: "application/json" } });
  if (!response.ok) throw new AccessDenied("cannot fetch Access signing keys");
  const body = (await response.json()) as { keys?: Jwk[] };
  cachedKeys = { url, at: Date.now(), keys: body.keys ?? [] };
  return cachedKeys.keys;
}

/** The verified email of the person behind `token`. Throws {@link AccessDenied}. */
export async function verifyAccessJwt(token: string, config: AccessConfig, now = Date.now()): Promise<string> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new AccessDenied("malformed token");
  const [headerText, payloadText, signatureText] = parts as [string, string, string];
  const header = b64urlJson(headerText);
  if (header.alg !== "RS256" || typeof header.kid !== "string") throw new AccessDenied("unsupported token");

  // A key we have not seen may be a rotation: look once more before refusing.
  let jwk = (await keys(config, false)).find((k) => k.kid === header.kid);
  if (!jwk && !config.jwks) jwk = (await keys(config, true)).find((k) => k.kid === header.kid);
  if (!jwk) throw new AccessDenied("token signed by an unknown key");
  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const signed = new TextEncoder().encode(`${headerText}.${payloadText}`);
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = b64urlBytes(signatureText);
  } catch {
    throw new AccessDenied("malformed token");
  }
  if (!(await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, signature, signed)))
    throw new AccessDenied("bad token signature");

  // Only now is the payload trusted enough to read.
  const claims = b64urlJson(payloadText);
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(config.audience)) throw new AccessDenied("token is for another application");
  if (claims.iss !== `https://${config.teamDomain}`) throw new AccessDenied("token from another issuer");
  const seconds = now / 1000;
  if (typeof claims.exp !== "number" || claims.exp + CLOCK_SKEW_S < seconds) throw new AccessDenied("token expired");
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_S > seconds) throw new AccessDenied("token not yet valid");
  if (typeof claims.email !== "string" || !claims.email.includes("@")) throw new AccessDenied("token names no person");
  return claims.email.toLowerCase();
}
