import { cloudflareTest, readD1Migrations } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig(async () => ({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.jsonc", environment: "staging" },
      miniflare: {
        bindings: {
          PLATFORM_ADMIN_TOKEN: "test-platform-admin-token",
          // 32 zero bytes: a test key, never a real one.
          KEY_ENCRYPTION_KEY: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
          TEST_MIGRATIONS: await readD1Migrations("./migrations"),
        },
      },
    }),
  ],
  test: { setupFiles: ["./test/setup.ts"] },
}));
