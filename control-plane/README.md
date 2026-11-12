# SafeStream control plane

A Cloudflare Worker at `api.safestreamdata.com` (staging: `api-staging.safestreamdata.com`).
It signs and distributes redaction policies and keeps what connectors report about themselves.

**It never receives record content.** Connectors pull policies and push audit events. An audit
event is checked field by field against an allow-list of counts, names, versions and hashes
(`src/validate.ts`); an unknown field or free text is refused, and tests hold that line.

## What it does

| For | Routes |
|---|---|
| The operator | `POST /v1/admin/tenants`: a tenant, its Ed25519 signing key and its first admin token |
| A tenant's admins | Issue and revoke connector tokens; publish field rules (signed as the next version, offered to connectors as the **candidate** for shadow evaluation); promote a version (a **staged rollout** by default); follow, resume or abort the rollout; withdraw a candidate; list connectors and audit-chain heads |
| Connectors | `GET /v1/agent/whoami`; `GET /v1/agent/policy/active` and `/candidate`; `POST /v1/agent/telemetry` |

`openapi.yaml` is the full contract; a test keeps it in step with the routes.

- **Tenant isolation.** A caller's tenant comes from its token, never from the request. No
  route takes a tenant id, so one tenant cannot name another's data.
- **Signing.** The control plane signs with a key per tenant. The private half is stored
  AES-GCM encrypted under the Worker's `KEY_ENCRYPTION_KEY`; the database alone cannot sign.
  Bundles are byte-compatible with `safestream-policy`, and a fixture verified by both the
  Worker's tests and the connector's keeps them that way.
- **Audit anchoring.** Each reported event must extend the recorded head of its hash chain.
  The head is kept here, outside the customer's own audit store, and is what
  `safestream-audit verify --head` checks. An event that does not extend the head is kept as
  evidence and the chain is marked broken.
- **Tokens** are 32 random bytes, stored only as SHA-256 hashes, and shown once.
- **Staged rollout** (`src/rollout.ts`). Promoting a version hands it to one connector, then
  to a tenth of the fleet, then to all of it. A connector names itself in
  `x-safestream-instance` when it fetches the active policy, and the cohort of a stage is the
  first N connectors seen in the last 10 minutes, ordered by a hash of tenant, version and
  connector name. A stage ends once every connector in it has reported an audit window under
  the version and `soak_seconds` (default 600) have passed. It halts on a leak canary, or on a
  DLQ rate more than one point above the rest of the fleet's (over windows of at least 100
  records). A halted rollout stays put until it is resumed (the stage starts over) or aborted.
  Neither can take the version back from connectors that already run it, because connectors
  refuse older policies. A newer version replaces the rollout.

  ```bash
  curl -sS https://api.safestreamdata.com/v1/policies/8/promote \
    -H "authorization: Bearer $ADMIN_TOKEN" -d '{"soak_seconds": 900}'
  curl -sS https://api.safestreamdata.com/v1/rollout -H "authorization: Bearer $ADMIN_TOKEN"
  ```

## Console

`app.safestreamdata.com` (staging: `app-staging.safestreamdata.com`), served by this same
Worker from `console/` (Workers static assets). No passwords and no tokens in the browser:

- **Two locks.** Cloudflare Access lets a person in through their own identity provider
  (`infra/cloudflare/access.tf`). The Worker then verifies Access's signed token itself
  (`src/access.ts`: RS256 against the team's certs, this application's audience, the issuer,
  the lifetime) and looks the email up in `console_users`. A person Access lets in still sees
  nothing until a tenant admin grants them a role. A missing or bad token gets nothing, not
  even the static page, so a misconfigured Access fails closed.
- **One API.** `/console/api/<route>` is the tenant-admin route `/v1/<route>`, run by the same
  handlers with the person's tenant and role in place of a token (`src/console.ts`). Agent
  routes and tenant creation are not reachable from the console. The console host serves
  nothing else, and the API hosts never serve the console.
- **Roles.** `viewer` reads. `admin` also publishes, rolls out, issues and revokes connector
  tokens, and manages console users. Someone in several tenants picks one; their role follows it.
- **Changes are guarded and logged.** A change must come from the console's own page: same
  origin, plus a header a cross-site form cannot set. Each change is logged as
  `{"event": "console_change", email, tenant, method, route}`, never with a body.
- **Strict page.** A content security policy allowing only the console's own script and
  connections, no framing, `nosniff`, no referrer. Nothing from the API is ever put into the
  page as HTML.

What it shows: fleet health (connectors reporting, silent ones, canary leaks, DLQ rates); the
policies with each version's rules, the rule diff against the version in force, and the
fleet's **shadow diff** (`GET /v1/shadow`: "this candidate would redact 600 more `id_number`
values and 0 fewer of anything"); a policy editor that signs and publishes the next version;
rollout control (staged or immediate, resume, abort, withdraw); **audit evidence export**
(`GET /v1/chains/{chain}/events`, every stored event byte for byte, with the anchored head);
and access management (console users, connector tokens).

Give someone access:

```bash
curl -sS https://api.safestreamdata.com/v1/console-users \
  -H "authorization: Bearer $ADMIN_TOKEN" -d '{"email": "ana@acme.example", "role": "admin"}'
```

Access must also let them through (`console_allowed_emails` or `console_allowed_email_domains`
in Terraform). Deploying needs the repository variable `ACCESS_TEAM_DOMAIN`; Terraform supplies
each application's audience tag.

## Develop

```bash
npm ci && npm test
```

Tests run inside workerd, the production runtime, with local D1 and R2. Nothing touches
Cloudflare. A throwaway RSA key stands in for Access's signing key, so the tests can mint
Access tokens, including forged, expired and wrong-audience ones.

Run it locally with the `local` environment (no routes, so `wrangler dev` keeps each request's
Host: the console answers on `localhost`, the API on `127.0.0.1`):

```bash
node e2e/access-key.mjs /tmp/ss
```

```bash
printf 'PLATFORM_ADMIN_TOKEN="ci-platform-admin"\nKEY_ENCRYPTION_KEY="%s"\n' "$(openssl rand -base64 32)" | cat - /tmp/ss/access.vars > /tmp/ss/dev.vars
```

```bash
npx wrangler d1 migrations apply DB --local --env local && npx wrangler dev --env local --ip 127.0.0.1 --env-file /tmp/ss/dev.vars
```

```bash
E2E_KEY_DIR=/tmp/ss node e2e/console.e2e.mjs
```

The last command is the browser test CI runs: Playwright drives the console through sign-in,
fleet, publishing, the shadow diff, a staged rollout that halts on a leak canary, export and
offline verification with `safestream-audit`, token issuance, and a viewer who cannot change
anything. CI also runs the Worker with `wrangler dev` and drives a real connector against it
(`tests/test_control_integration.py` in the repository root). `test/fixtures/audit-event.json`
is an event as the connector builds it: the Python tests keep it in step with the connector,
and the tests here must accept it.

## Deploy

The `Deploy` workflow does it after Terraform has created the databases and buckets. It needs
two more GitHub secrets, each a JSON object, one per environment:

```json
{ "PLATFORM_ADMIN_TOKEN": "<long random string>", "KEY_ENCRYPTION_KEY": "<openssl rand -base64 32>" }
```

- `PLATFORM_ADMIN_TOKEN` creates tenants. Keep it in a password manager.
- `KEY_ENCRYPTION_KEY` encrypts every tenant's signing key. **Back it up and never change
  it**: with a different value the stored keys cannot be decrypted, and every tenant would
  need a new signing key rolled out to all its connectors.

Staging deploys on every push to `main` that touches this directory. Production deploys only
when the workflow is run by hand with the production box ticked.

## First tenant

```bash
curl -sS https://api-staging.safestreamdata.com/v1/admin/tenants \
  -H "authorization: Bearer $PLATFORM_ADMIN_TOKEN" -d '{"id": "acme", "name": "Acme Inc"}'
```

The response holds the tenant's admin token (shown once) and the public key its connectors
must trust (`SAFESTREAM_POLICY_PUBLIC_KEYS`).

## Not built yet

- During a rollout, the cohort is recomputed on every active-policy request (a hash per live
  connector). That is fine for fleets of hundreds; a large fleet would cache it per stage.
- Telemetry is written in the request, not through a queue. At one event per connector per
  minute that is ample; a queue goes in front when volume calls for it.
- Field rules are checked for structure here and in full by the connector, which refuses a
  bundle it cannot use. A misspelt entity type is therefore caught as a rejected candidate,
  not at publish time.
