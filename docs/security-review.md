# Security review: control plane and console

A review of everything on `safestreamdata.com` before design partners use it: the Worker
(`control-plane/src/`), the console (`control-plane/console/`), the connector's uplink
(`src/safestream_enterprise/control.py`) and the Cloudflare configuration
(`infra/cloudflare/`). Date: 2026-11-12, at the commit that adds this file.

## Fixed in this review

| Finding | Risk | Fix |
|---|---|---|
| Request bodies were read whole into memory before the 64 KiB limit was checked, and no edge rule caps body size | Any caller, even without a valid token, could make the Worker buffer a large body before it answered 413: memory and CPU spent per request | `readCapped` refuses on a declared `Content-Length` over the limit, and otherwise stops reading a streamed body as soon as it passes the limit (test: a 1 MiB body streamed without a length) |
| A console token naming an unknown key id made the Worker refetch Access's keys every time | Requests could be turned into a stream of fetches to the Access certs endpoint | At most one refetch a minute (test: five unknown-key tokens, one fetch) |
| The test-only `ACCESS_JWKS` override was honoured on any host | If that variable ever reached a real deployment, whoever held the matching private key could sign in as anyone | Honoured only when the console is served on `localhost` or a `.test` host; on a real host the console refuses to serve (test) |

Found by the load test in the same phase, and also fixed: during a staged rollout every
active-policy request read every live connector and hashed each name, halving the Worker's
throughput at a few hundred connectors. The cohort is now cached per tenant, version and stage
for 15 seconds. See [Control-plane load test](#control-plane-load-test).

## Checked and holding

- **Tenant isolation.** Every handler takes the tenant from the caller's token or console
  session, never from the request. Every query and every R2 key is scoped by it. The Worker's
  tests try each route across two tenants.
- **Tokens.** 32 random bytes, stored only as SHA-256 hashes, shown once, revocable with
  immediate effect. Admin and connector tokens are separate kinds, and each route checks the kind.
- **Policy integrity.** Bundles are signed with a per-tenant Ed25519 key, which is stored
  AES-GCM encrypted under a Worker secret. The connector verifies every bundle with keys
  configured in the cluster, so a compromised control plane can distribute only bundles signed
  with the tenant's key, and cannot roll a connector back.
- **No record content.** The one upload route takes audit events, checked field by field
  against an allow-list of counts, names, versions and hashes. The connector applies the same
  allow-list before sending. A shared fixture is tested on both sides.
- **Console sign-in.** The Worker verifies the Access JWT itself: RS256 only, a known key id,
  the signature, this application's audience, the team issuer, expiry and not-before (60 s
  skew), and an email claim. The tests cover forged payloads, `alg: none`, unknown keys and
  wrong audience, issuer and lifetime. Without a valid token nothing is served, not even the
  static page.
- **Console authorization.** One code path: console requests run the token API's own
  handlers with the person's tenant and role. Only tenant-admin routes are reachable (an
  allow-list); agent routes and tenant creation are not. Viewers cannot change anything; the
  test forces a change from a viewer's page.
- **CSRF.** Access authenticates by cookie, so every console change must carry the console's
  marker header and a same-origin `Origin`. A cross-site form or fetch can send neither.
- **XSS and framing.** Strict CSP (`script-src 'self'`, no inline script, `frame-ancestors
  'none'`, `form-action 'none'`). The console builds every element with `textContent` and
  never parses API data as HTML.
- **Hosts.** The console host serves only the console (behind Access); the API hosts never
  serve it. A token does nothing on the console host.
- **Uplink.** Outbound HTTPS only, redirects never followed (a redirect would carry the
  token), plain HTTP refused except to `localhost`, response bodies capped at 1 MiB, the token
  never in a log or error message.
- **Errors.** Unexpected errors return a generic 500. Validation messages name the field and
  never echo a value.

## Accepted risks

- **A connector token holder can write audit evidence for its tenant.** The evidence is
  bounded by the per-IP rate limit and the body cap, and each event is checked. Revoke a leaked
  token (runbook: [A connector token is compromised](runbooks.md#a-connector-token-is-compromised)).
- **A connector can name itself anything,** within its own tenant, in `x-safestream-instance`
  and in its audit events. That can place it in a rollout cohort. It cannot get a bundle that
  is not already signed for its tenant, and candidates are distributed to every connector anyway.
- **Console identity is the email Access asserts.** An identity provider that lets users choose
  unverified emails would let them claim someone else's. Allow only providers that verify
  email (`console_identity_providers` in Terraform).
- **Console changes are logged with the person's email,** in the Worker's logs: the audit
  trail of who changed what. Bodies are never logged.
- **No rotation API for a tenant's signing key yet.** A suspected key compromise needs an
  operator procedure: a new tenant key, and `SAFESTREAM_POLICY_PUBLIC_KEYS` updated on that
  tenant's connectors. Building the rotation API is on the list.
- **`KEY_ENCRYPTION_KEY` cannot be rotated in place.** Changing it makes every stored signing
  key unreadable. Keep it backed up (runbook: [Backup and restore](runbooks.md#backup-and-restore)).

## Not yet done

- An external scan (OWASP ZAP baseline) against staging, once staging is deployed.
- A review of the live Cloudflare configuration (Access policies, WAF events) after the first apply.

## Control-plane load test

`control-plane/load/fleet.mjs` simulates a fleet at a multiple of its real cadence: each
connector polls two policies every 30 s and reports one event a minute. The measured numbers,
and what they do and do not mean, are in [benchmarks](benchmarks.md#control-plane).
