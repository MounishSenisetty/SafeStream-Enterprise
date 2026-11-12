// Makes a throwaway RSA key that stands in for Cloudflare Access's signing key
// in a local run of the console (wrangler dev + e2e/console.e2e.mjs):
//   node e2e/access-key.mjs <dir>
// writes <dir>/access-private.jwk.json (for the test, to mint Access tokens)
// and <dir>/access.vars (lines to append to wrangler dev's --env-file).
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dir = process.argv[2];
if (!dir) {
  console.error("usage: node e2e/access-key.mjs <dir>");
  process.exit(2);
}
mkdirSync(dir, { recursive: true });
const pair = await crypto.subtle.generateKey(
  { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
  true,
  ["sign", "verify"],
);
const pub = { ...(await crypto.subtle.exportKey("jwk", pair.publicKey)), kid: "e2e-key", use: "sig" };
const priv = { ...(await crypto.subtle.exportKey("jwk", pair.privateKey)), kid: "e2e-key" };
writeFileSync(join(dir, "access-private.jwk.json"), JSON.stringify(priv), { mode: 0o600 });
writeFileSync(
  join(dir, "access.vars"),
  [
    'CONSOLE_HOST="localhost"',
    'ACCESS_TEAM_DOMAIN="e2e-team.cloudflareaccess.com"',
    'ACCESS_AUD="e2e-console-aud"',
    `ACCESS_JWKS='${JSON.stringify({ keys: [pub] })}'`,
    "",
  ].join("\n"),
);
