// End-to-end test of the console in a real browser, against the real Worker
// running under wrangler dev (local D1 and R2: nothing touches Cloudflare).
//
//   node e2e/access-key.mjs "$DIR"           # once, before starting wrangler dev
//   wrangler dev ... --env-file <secrets + $DIR/access.vars>
//   E2E_KEY_DIR="$DIR" node e2e/console.e2e.mjs
//
// The console is served on CONSOLE_HOST=localhost and the API on 127.0.0.1,
// the way app. and api. are split in production. Cloudflare Access is played
// by this script: it signs the Access token the Worker verifies.
//
// Covers: sign-in refused without a valid token; fleet health; publishing a
// policy from the editor; the shadow diff of the candidate; a staged rollout
// that halts on a leak canary, then is aborted; exporting a chain and
// verifying it offline with safestream-audit; issuing a connector token;
// a viewer who cannot change anything.

import { execFileSync } from "node:child_process";
import { readFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const PORT = process.env.E2E_PORT ?? "8787";
const API = `http://127.0.0.1:${PORT}`;
const APP = `http://localhost:${PORT}`;
const PLATFORM = process.env.E2E_PLATFORM_TOKEN ?? "ci-platform-admin";
const KEY_DIR = process.env.E2E_KEY_DIR;
const OUT = process.env.E2E_OUT ?? join(KEY_DIR ?? ".", "e2e-out");
const AUDIT = (process.env.SAFESTREAM_AUDIT_CMD ?? "safestream-audit").split(" ");
mkdirSync(OUT, { recursive: true });

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures += 1;
};

// ---------------------------------------------------------------- Access

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const privateJwk = JSON.parse(readFileSync(join(KEY_DIR, "access-private.jwk.json"), "utf8"));
const signingKey = await crypto.subtle.importKey("jwk", privateJwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);

async function accessJwt(email) {
  const now = Math.floor(Date.now() / 1000);
  const head = b64url(JSON.stringify({ alg: "RS256", kid: "e2e-key", typ: "JWT" }));
  const body = b64url(
    JSON.stringify({ aud: ["e2e-console-aud"], iss: "https://e2e-team.cloudflareaccess.com", email, iat: now, exp: now + 3600, type: "app" }),
  );
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", signingKey, new TextEncoder().encode(`${head}.${body}`));
  return `${head}.${body}.${b64url(new Uint8Array(sig))}`;
}

// ---------------------------------------------------------------- API seed

async function api(method, path, token, body) {
  const response = await fetch(API + path, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  const text = await response.text();
  if (!response.ok) throw new Error(`${method} ${path}: HTTP ${response.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

const sha256 = async (text) =>
  "sha256:" + Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))).toString("hex");

const tenantId = `e2e-${Date.now().toString(36)}`;
const tenant = await api("POST", "/v1/admin/tenants", PLATFORM, { id: tenantId, name: "E2E Inc" });
const admin = tenant.admin_token;
const agent = (await api("POST", "/v1/agent-tokens", admin, { label: "e2e cluster" })).token;
// Unique per run, so reruns against the same local database stay one tenant each.
const ADA = `ada+${tenantId}@e2e.example`;
const VIV = `viv+${tenantId}@e2e.example`;
await api("POST", "/v1/console-users", admin, { email: ADA, role: "admin" });
await api("POST", "/v1/console-users", admin, { email: VIV, role: "viewer" });
await api("POST", "/v1/policies", admin, { field_rules: { mode: "extend", rules: {}, disable: [] } });
await api("POST", "/v1/policies/1/promote", admin, { strategy: "immediate" });

/** A connector reporting audit windows on its own chain. */
function connector(instance) {
  let seq = 0;
  let prev = null;
  const sent = [];
  return {
    instance,
    sent,
    chain: `${instance}-chain`,
    async report({ version = 1, shadow = null, leaks = 0, final = false } = {}) {
      const body = JSON.stringify({
        schema: "safestream.audit/v2",
        connector_version: "0.3.0",
        instance,
        group_id: "safestream-redactor",
        topics: { ingress: "ingress-logs", egress: "egress-logs-clean", dlq: "ingress-logs-dlq" },
        delivery: "exactly_once",
        redaction_mode: "pseudonymize",
        field_rules: { count: 66, fingerprint: "sha256:" + "ab".repeat(32) },
        policy: { tenant: tenantId, version, key_id: tenant.key_id },
        shadow,
        chain: { id: `${instance}-chain`, seq, prev },
        window: { start: new Date(Date.now() - 60_000).toISOString(), end: new Date().toISOString(), final },
        records: { egress: 1000, dlq: 1 },
        redactions: { email: 800 },
        batches: 10,
        transaction_aborts: 0,
        canary: { checks: 2, leaks },
      });
      await api("POST", "/v1/agent/telemetry", agent, body);
      sent.push(body);
      seq += 1;
      prev = await sha256(body);
    },
  };
}
const pods = ["pod-a", "pod-b", "pod-c"].map(connector);
for (const pod of pods) await pod.report();

// ---------------------------------------------------------------- browser

const browser = await chromium.launch();
const shot = (page, name) => page.screenshot({ path: join(OUT, `${name}.png`), fullPage: true });

try {
  // Nobody gets in without Access, not even to the page.
  const anonymous = await browser.newContext();
  const refused = await (await anonymous.newPage()).goto(APP + "/");
  check(refused.status() === 403, "no Access token: the console refuses to serve anything");
  await anonymous.close();

  // ---- admin
  const context = await browser.newContext({
    extraHTTPHeaders: { "cf-access-jwt-assertion": await accessJwt(ADA) },
    acceptDownloads: true,
  });
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("console", (m) => m.type() === "error" && consoleErrors.push(m.text()));
  page.on("pageerror", (e) => consoleErrors.push(String(e)));

  await page.goto(APP + "/");
  await page.getByText("connectors reporting").waitFor();
  check((await page.locator("#email").textContent()) === ADA, "signed in as the Access identity");
  const rows = await page.locator("main tbody tr").count();
  check(rows === 3, `fleet lists the 3 reporting connectors (${rows})`);
  check((await page.locator(".badge.ok", { hasText: "healthy" }).count()) === 3, "all 3 shown healthy");
  await shot(page, "1-fleet");

  // Publish version 2 from the editor: it becomes the candidate.
  await page.locator('#tabs button[data-tab="policies"]').click();
  await page.locator("#rules").waitFor();
  await page.locator("#rules").fill(JSON.stringify({ mode: "extend", rules: { "*member_id*": "id_number" }, disable: [] }, null, 2));
  await page.locator("#publish").click();
  await page.locator("#notice:not([hidden])").waitFor();
  check((await page.locator("#notice").textContent()) === "Published as the candidate", "publish reported success");
  const list = await api("GET", "/v1/policies", admin);
  check(list.candidate_version === 2, `the editor published a signed version 2 as the candidate (${JSON.stringify(list.policies.map((p) => p.version))}, candidate ${list.candidate_version})`);

  // The connectors evaluate it in shadow and report counts: the console sums them.
  const shadow = (records, ids) => ({
    candidate: { tenant: tenantId, version: 2, key_id: tenant.key_id },
    since: new Date(Date.now() - 120_000).toISOString().replace(/\.\d+Z$/, "+00:00"),
    records,
    changed_records: ids,
    errors: 0,
    redactions: { active: { email: records }, candidate: { email: records, id_number: ids } },
  });
  for (const [i, pod] of pods.entries()) await pod.report({ shadow: shadow(1000, 100 * (i + 1)) });
  await page.reload();
  await page.getByText("Shadow evaluation of version 2").waitFor();
  const idRow = page.locator("main tr", { hasText: "id_number" }).filter({ hasText: "+600" });
  check((await idRow.count()) === 1, "shadow diff: promoting would add 600 id_number redactions");
  check((await page.locator("main tr", { hasText: "added" }).count()) >= 1, "rule diff shows the added *member_id* rule");
  await shot(page, "2-policies-shadow");

  // Staged rollout; the first connector reports a leak canary; it halts.
  await page.locator('#tabs button[data-tab="rollout"]').click();
  await page.locator("#soak").fill("0");
  await page.locator("#promote").click();
  await page.getByText("Rollout of version 2 started").waitFor();
  const rollout = (await api("GET", "/v1/rollout", admin)).rollout;
  check(rollout?.stage === "first_agent" && rollout.cohort.length === 1, "staged rollout began with one connector");
  const first = pods.find((p) => p.instance === rollout.cohort[0]);
  await first.report({ version: 2, leaks: 1 });
  await page.reload();
  await page.locator("#halt-reason").waitFor();
  check((await page.locator("#halt-reason").textContent()).includes(`leak canary failed on ${first.instance}`), "rollout halted on the leak canary, and says why");
  await shot(page, "3-rollout-halted");
  page.once("dialog", (d) => d.accept());
  await page.getByRole("button", { name: "Abort" }).click();
  await page.getByText("Rollout aborted").waitFor();
  check((await api("GET", "/v1/rollout", admin)).rollout === null, "rollout aborted from the console");

  // Export a closed chain and verify it offline against the anchored head.
  const pod = pods.find((p) => p !== first);
  await pod.report({ final: true });
  await page.locator('#tabs button[data-tab="evidence"]').click();
  const exportButton = page.locator(`button[data-chain="${pod.chain}"]`);
  await exportButton.waitFor();
  const [download] = await Promise.all([page.waitForEvent("download"), exportButton.click()]);
  const file = join(OUT, `${pod.chain}.ndjson`);
  await download.saveAs(file);
  check(readFileSync(file, "utf8") === pod.sent.join("\n") + "\n", "exported chain is byte for byte what the connector sent");
  const head = (await api("GET", "/v1/chains", admin)).chains.find((c) => c.chain === pod.chain).head;
  let verified = false;
  try {
    const out = execFileSync(AUDIT[0], [...AUDIT.slice(1), "verify", file, "--head", `${pod.chain}=${head}`, "--require-closed"], { encoding: "utf8" });
    verified = JSON.parse(out).intact === true;
  } catch (err) {
    console.log(String(err.stdout ?? err));
  }
  check(verified, "safestream-audit verify: the export is intact and contains the anchored head");
  await shot(page, "4-evidence");

  // Issue a connector token; it is shown once.
  await page.locator('#tabs button[data-tab="access"]').click();
  await page.locator("#token-label").fill("prod-eu-1");
  await page.locator("#issue").click();
  await page.locator("#issued pre").waitFor();
  check((await page.locator("#issued pre").textContent()).includes("SAFESTREAM_CONTROL_TOKEN=sst_agent_"), "issued a connector token from the console");
  await shot(page, "5-access");
  check(consoleErrors.length === 0, `no errors in the browser console (${consoleErrors.join(" | ")})`);
  await context.close();

  // ---- viewer: reads, cannot change anything.
  const viewer = await browser.newContext({ extraHTTPHeaders: { "cf-access-jwt-assertion": await accessJwt(VIV) } });
  const vpage = await viewer.newPage();
  await vpage.goto(APP + "/#policies");
  await vpage.locator("#publish").waitFor();
  check(await vpage.locator("#publish").isDisabled(), "viewer: publish is disabled");
  check((await vpage.locator("#role").textContent()) === "viewer", "viewer: role shown");
  const forced = await vpage.evaluate(async () => {
    const r = await fetch("/console/api/policies", {
      method: "POST",
      headers: { "content-type": "application/json", "x-safestream-console": "1" },
      body: JSON.stringify({ field_rules: { rules: {} } }),
    });
    return r.status;
  });
  check(forced === 403, "viewer: a forced change is refused by the Worker");
  await viewer.close();
} finally {
  await browser.close();
}

console.log(failures ? `${failures} check(s) failed` : "all checks passed");
process.exit(failures ? 1 : 0);
