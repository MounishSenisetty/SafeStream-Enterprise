// Backup and restore drill, the two halves run by drills/restore-drill.sh:
//   node drills/drill.mjs seed   <url> <platform token> <state file>
//   node drills/drill.mjs verify <url> <state file>
// seed writes a tenant with a policy and an audit chain, and records what a
// restore must bring back. verify checks a Worker running on restored storage.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";

const [mode, url, ...rest] = process.argv.slice(2);
const sha256 = async (text) => "sha256:" + Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))).toString("hex");

async function call(method, path, token, body) {
  const response = await fetch(url + path, {
    method,
    headers: { authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "content-type": "application/json" }) },
    body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, text, headers: response.headers };
}
async function must(method, path, token, body) {
  const r = await call(method, path, token, body);
  if (r.status >= 300) throw new Error(`${method} ${path}: HTTP ${r.status} ${r.text}`);
  return r;
}

let failures = 0;
const check = (ok, what) => {
  console.log(`${ok ? "PASS" : "FAIL"}  ${what}`);
  if (!ok) failures += 1;
};

if (mode === "seed") {
  const [platform, stateFile] = rest;
  const id = `drill-${Date.now().toString(36)}`;
  const tenant = JSON.parse((await must("POST", "/v1/admin/tenants", platform, { id, name: "Drill" })).text);
  const agent = JSON.parse((await must("POST", "/v1/agent-tokens", tenant.admin_token, { label: "drill" })).text);
  await must("POST", "/v1/policies", tenant.admin_token, { field_rules: { rules: { "*member_id*": "id_number" } } });
  await must("POST", "/v1/policies/1/promote", tenant.admin_token, { strategy: "immediate" });
  const bundle = (await must("GET", "/v1/agent/policy/active", agent.token)).text;
  let prev = null;
  const chain = "drill-pod-chain";
  for (let seq = 0; seq < 5; seq++) {
    const event = JSON.stringify({
      schema: "safestream.audit/v2", connector_version: "0.3.0", instance: "drill-pod", group_id: "g",
      topics: { ingress: "in", egress: "out", dlq: "dlq" }, delivery: "exactly_once", redaction_mode: "replace",
      field_rules: { count: 1, fingerprint: "sha256:" + "ab".repeat(32) },
      policy: { tenant: id, version: 1, key_id: tenant.key_id }, shadow: null,
      chain: { id: chain, seq, prev },
      window: { start: "2026-11-12T09:00:00.000+00:00", end: "2026-11-12T09:01:00.000+00:00", final: seq === 4 },
      records: { egress: 100, dlq: 0 }, redactions: { email: 10 }, batches: 1, transaction_aborts: 0, canary: { checks: 2, leaks: 0 },
    });
    await must("POST", "/v1/agent/telemetry", agent.token, event);
    prev = await sha256(event);
  }
  writeFileSync(stateFile, JSON.stringify({ tenant: id, admin: tenant.admin_token, agent: agent.token, publicKey: tenant.public_key, bundleDigest: await sha256(bundle), chain, head: prev }));
  console.log(`seeded tenant ${id}: policy 1 active, chain ${chain} with 5 events, head ${prev}`);
} else if (mode === "verify") {
  const [stateFile] = rest;
  const s = JSON.parse(readFileSync(stateFile, "utf8"));
  const policies = JSON.parse((await must("GET", "/v1/policies", s.admin)).text);
  check(policies.active_version === 1, "tenant, its admin token and its active policy survived");
  const bundle = await call("GET", "/v1/agent/policy/active", s.agent);
  check(bundle.status === 200 && (await sha256(bundle.text)) === s.bundleDigest, "connector token works and gets the identical signed bundle");
  const chains = JSON.parse((await must("GET", "/v1/chains", s.admin)).text).chains;
  const chain = chains.find((c) => c.chain === s.chain);
  check(chain?.head === s.head && chain.closed === 1 && chain.broken === 0, "audit chain head is the one recorded before the backup");
  const exported = await must("GET", `/v1/chains/${s.chain}/events`, s.admin);
  const file = `${stateFile}.chain.ndjson`;
  writeFileSync(file, exported.text);
  let intact = false;
  try {
    intact = JSON.parse(execFileSync("safestream-audit", ["verify", file, "--head", `${s.chain}=${s.head}`, "--require-closed"], { encoding: "utf8" })).intact;
  } catch (err) {
    console.log(String(err.stdout ?? err));
  }
  check(intact, "restored evidence verifies offline against the pre-backup head");
  // The tenant's signing key is stored encrypted; signing proves it still decrypts.
  const next = await call("POST", "/v1/policies", s.admin, { field_rules: { rules: {} } });
  check(next.status === 201 && JSON.parse(next.text).version === 2, "a new policy can be signed after the restore (signing key decrypts)");
  console.log(failures ? `${failures} check(s) failed` : "restore drill passed");
  process.exit(failures ? 1 : 0);
} else {
  console.error("usage: drill.mjs seed <url> <platform token> <state> | verify <url> <state>");
  process.exit(2);
}
