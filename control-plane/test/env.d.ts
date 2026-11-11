// Bindings available to tests through `env` from "cloudflare:test".
declare namespace Cloudflare {
  interface Env {
    DB: D1Database;
    POLICIES: R2Bucket;
    AUDIT: R2Bucket;
    PLATFORM_ADMIN_TOKEN: string;
    KEY_ENCRYPTION_KEY: string;
    TEST_MIGRATIONS: import("@cloudflare/vitest-plugin").D1Migration[];
  }
}

declare module "*?raw" {
  const text: string;
  export default text;
}
