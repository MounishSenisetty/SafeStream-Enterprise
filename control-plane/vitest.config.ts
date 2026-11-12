import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// A throwaway key standing in for Cloudflare Access's signing key: the tests
// mint Access tokens with the private half, the Worker trusts the public half.
async function accessTestKey() {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  return {
    publicJwk: { ...((await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey), kid: "test-key-1", use: "sig" },
    privateJwk: { ...((await crypto.subtle.exportKey("jwk", pair.privateKey)) as JsonWebKey), kid: "test-key-1" },
  };
}

export default defineConfig(async () => {
  const { publicJwk, privateJwk } = await accessTestKey();
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: "./wrangler.jsonc", environment: "staging" },
        miniflare: {
          bindings: {
            PLATFORM_ADMIN_TOKEN: "test-platform-admin-token",
            // 32 zero bytes: a test key, never a real one.
            KEY_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            TEST_MIGRATIONS: await readD1Migrations("./migrations"),
            CONSOLE_HOST: "app.test",
            ACCESS_TEAM_DOMAIN: "test-team.cloudflareaccess.com",
            ACCESS_AUD: "test-console-aud",
            ACCESS_JWKS: JSON.stringify({ keys: [publicJwk] }),
            TEST_ACCESS_PRIVATE_JWK: JSON.stringify(privateJwk),
          },
        },
      }),
    ],
    test: { setupFiles: ["./test/setup.ts"] },
  };
});
