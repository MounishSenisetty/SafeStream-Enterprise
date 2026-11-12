# Runbooks

What to do when something goes wrong, written for the person on call. Each runbook starts
from the signal you see (an alert, a console badge, an exit code), says what it means for
data, and lists the steps in order. Commands assume `ADMIN_TOKEN` holds the tenant's admin
token and `API` the control plane (`https://api.safestreamdata.com`).

Two facts shape every runbook below:

- **The connector fails closed.** Whatever breaks, an unredacted record does not reach the
  clean topic. Outages cost freshness (records wait on the ingress topic), not privacy.
- **Policies never go backwards.** A connector refuses any policy older than the one it runs.
  You fix a bad policy by publishing a newer one, never by rolling back.

## A leak canary failed

**Signal.** Alert `SafeStreamCanaryLeak`; `safestream_canary_leaks_total` above zero; the
console's fleet view shows **canary leak**; a staged rollout halts with "leak canary failed on
…". In the connector log: `LEAK CANARY: synthetic PII survived redaction (json, xml) under policy N`.

**What it means.** Records carrying freshly made-up PII came out of the live redactor with
some of it intact. Real records under the same policy may be reaching the clean topic with
PII. Treat it as a data incident until shown otherwise.

1. **Stop the spread.** If a rollout is in progress, it has already halted; abort it
   (`POST $API/v1/rollout/abort`, or **Abort** on the console's Rollout tab).
2. **Find the policy.** `safestream_policy_version` on the affected pods, and the `policy`
   field of their audit events. Compare its rules with the previous version on the console's
   Policies tab (the rule diff): a removed rule, a `disable` entry, or `mode: replace`
   dropping built-in rules are the usual causes.
3. **Contain.** To stop publishing at once, set `SAFESTREAM_CANARY_ON_LEAK=stop` (chart
   value `canary.onLeak: stop`) and roll the pods. They exit with code 4 on the next canary
   and restart into the same check, so nothing more is published under that policy. Records
   wait on the ingress topic.
4. **Fix.** Publish a corrected policy as a new version and promote it with
   `{"strategy": "immediate"}`. Connectors on the bad version accept it because it is newer.
5. **Verify.** `safestream_canary_leaks_total` stops increasing, and the fleet view shows healthy.
6. **Assess.** The audit events of the affected windows give the instance, the time range and
   the counts of what went through under the bad version. Re-redact those records from the
   clean topic or its downstream stores with `safestream-batch` under the corrected policy.

## A rollout halted

**Signal.** `GET $API/v1/rollout` shows `"halted": true`; the console's Rollout tab shows the
reason in red.

**What it means.** A connector running the new version reported a leak canary, or a DLQ rate
more than one point above the rest of the fleet's. The version stopped spreading. Connectors
already on it keep it.

1. Read the reason. It names the connector and the version.
2. **Canary leak:** follow [A leak canary failed](#a-leak-canary-failed).
3. **DLQ rate:** the new rules make records fail. Look at the `x-safestream-error` header on
   that connector's dead-lettered records (`safestream-dlq summary`). An invalid or
   over-broad rule is usual. Publish a fix as a newer version; it replaces the halted rollout.
4. **A false alarm** (for example, a producer sent bad records at the same moment): resume
   (`POST $API/v1/rollout/resume`). The stage starts over, soak time included.
5. Once a newer version is rolling out, or the rollout is aborted, replay any records the bad
   version dead-lettered: `safestream-dlq replay`.

## The control plane is unreachable

**Signal.** Alert `SafeStreamControlPlaneUnreachable`; `safestream_control_connected 0`;
`safestream_control_queue_depth` growing.

**What it means.** Redaction carries on under the last policy each connector verified. New
policies do not arrive. Audit events wait in each connector's queue (1,000 events: about 16
hours at one a minute). Beyond that the oldest are dropped, and the control plane later marks
those chains as broken. Your own audit topic, if configured, is unaffected.

1. Check `https://api.safestreamdata.com/healthz` from outside the cluster. If it fails, it
   is the control plane; check the Cloudflare status page and the Worker's logs.
2. If it answers, it is the path from the cluster: the NetworkPolicy egress (`control.egress`
   in the chart), the egress proxy (`control.httpsProxy`), or a TLS-inspecting proxy whose CA
   the connector does not trust (`SAFESTREAM_CONTROL_CA_FILE`). From a pod's namespace:
   `safestream-control check` reports which step fails.
3. HTTP 401 in the connector log means its token was revoked: issue a new one (console Access
   tab) and update the Secret.
4. A pod that restarts during the outage starts on `SAFESTREAM_POLICY_FILE` if it is mounted.
   Without one it exits (code 1) until the control plane answers. Mount the last policy bundle
   as that file if an outage looks long.

## An audit chain is broken

**Signal.** `GET $API/v1/chains` shows `"broken": 1`; the console's Audit evidence tab shows
**broken**; `safestream-audit verify` reports a problem.

**What it means.** The control plane received an event that does not extend the head it
anchored. Either events were lost on the way (a connector queue overflowed during an outage),
or events were altered, removed or replayed. The out-of-place event is kept as evidence.

1. Export the chain (console, or `GET $API/v1/chains/<chain>/events`) and run
   `safestream-audit verify <file> --head <chain>=<anchored head>`. The output names the
   first sequence number that is missing, out of order, or altered.
2. Compare with your audit topic, if you have one: export it and verify it the same way. The
   same gap in both, right after a known control-plane outage, means lost in transit. A gap
   only in one copy, or an event that differs, means tampering: treat it as a security
   incident and keep both copies.
3. A broken chain stays broken. It covers one run of one connector; the next restart starts a
   new chain.

## A connector token is compromised

**Signal.** A token was exposed (a log, a ticket, a leaked Secret), or `GET $API/v1/agents`
lists connectors you do not run.

**What it means.** A token lets its holder download the tenant's signed policies (which are
rules, not data) and report audit events under the tenant. It cannot sign policies, read
other tenants, or reach any record.

1. Revoke it: `POST $API/v1/tokens/<id>/revoke` (ids from `GET $API/v1/tokens`), or
   **Revoke** on the console's Access tab. It stops working at once.
2. Issue a new token, update the Secret (`control-token`), and roll the connector pods.
3. Chains reported with the old token stay anchored and verifiable. Events sent by someone
   else under the stolen token show as unknown instances in `GET $API/v1/agents`, and as
   chains you cannot match to your pods.

## Console access

- **Give access.** Two steps: Access must let the person through (`console_allowed_emails` or
  `console_allowed_email_domains` in Terraform), and a tenant admin grants a role
  (`POST $API/v1/console-users {"email": …, "role": "viewer" | "admin"}`, or the console's
  Access tab).
- **Remove access.** `POST $API/v1/console-users/remove {"email": …}` takes effect on the
  next request. Also remove them from the Access policy or the identity provider.
- **Someone sees "has no access to any tenant".** Access let them in, but no tenant granted
  them a role. That is the second lock working.
- **The console answers 503 "not configured".** `ACCESS_TEAM_DOMAIN` or `ACCESS_AUD` is not
  set on the deployment (see `infra/cloudflare/README.md`). "Misconfigured" means the
  test-only `ACCESS_JWKS` variable is set on a real host. Remove it.

## Onboarding a design partner

1. **Tenant.** The operator creates it: `POST $API/v1/admin/tenants {"id": "acme", "name": "Acme"}`
   with the platform admin token. Hand the returned admin token to the partner over a channel
   you would trust with a password. It is shown once.
2. **Identity.** Add the partner's identity provider in Zero Trust, and their email domain to
   `console_allowed_email_domains`. Their admin grants console roles from then on.
3. **Connectors.** The partner issues a connector token per deployment (console Access tab)
   and installs the chart with `control.enabled=true`, `policy.publicKeys` (from the token
   response) and `policy.tenant`. `safestream-control check` confirms the setup before the
   first pod starts.
4. **First policy.** Publish, watch the shadow diff, then promote (staged).

## Backup and restore

**What holds what.**

| Store | Contents | If lost |
|---|---|---|
| D1 (per environment) | Tenants, wrapped signing keys, token hashes, policy metadata, rollout state, chain heads, fleet state | Everything stops; restore it |
| R2 policies bucket | Signed policy bundles | Connectors keep their policy; agents get 500 for missing bundles; publish a new version per tenant |
| R2 audit bucket | Uploaded audit events (the evidence) | Anchors (chain heads) survive in D1, but exports of lost chains are empty |
| Worker secret `KEY_ENCRYPTION_KEY` | Decrypts every tenant's signing key | No tenant can sign a new policy. Keep it in a password manager; it cannot be recovered |

**Point-in-time restore of D1** (Time Travel keeps 30 days):

```bash
npx wrangler d1 time-travel info safestream-production
```

```bash
npx wrangler d1 time-travel restore safestream-production --timestamp=2026-11-12T09:00:00Z
```

A restore rewinds rollouts, tokens and chain heads to that moment. Afterwards, connectors
report chain events beyond the restored heads, so those chains show as broken: expected after
a restore. Tokens issued after the timestamp stop working; reissue them.

**R2.** Production audit evidence can be made write-once (`audit_lock_days` in Terraform), so it
cannot be deleted or overwritten for that many days. R2 has no point-in-time restore. Copy the
audit bucket to a second bucket, in another account or jurisdiction, on a schedule, with any
S3-compatible tool and an R2 API token, for example `rclone sync`.

**The drill.** `control-plane/drills/restore-drill.sh` runs the restore locally. It seeds a
tenant, a policy and an audit chain on one Worker, exports D1 to SQL and copies R2, loads the
SQL into a new, empty database, and checks a second Worker on the restored storage:

- the tenant, its admin token and its active policy came back;
- the connector token works and gets the identical signed bundle;
- the chain's head is the one recorded before the backup;
- the evidence verifies offline against that head (`safestream-audit verify --head`);
- a new policy can be signed, which proves the restored signing key still decrypts.

Run it after any migration, and before relying on a backup. The production restore (Time
Travel and the R2 copy) has not been exercised yet: it needs the live account.

## Connector exit codes

| Code | Meaning | What to do |
|---|---|---|
| 0 | Clean stop | Nothing |
| 1 | Kafka error, or the control plane unreachable at startup with no policy file to start on | Check the brokers; see [The control plane is unreachable](#the-control-plane-is-unreachable) |
| 2 | Invalid configuration | The log names the setting; fix the values or the Secret |
| 3 | Stalled: the main loop stopped advancing (a Kafka client call never returned) | Restarts on its own and resumes from the last commit; repeated, check broker health |
| 4 | Stopped by a leak canary (`SAFESTREAM_CANARY_ON_LEAK=stop`) | See [A leak canary failed](#a-leak-canary-failed) |
