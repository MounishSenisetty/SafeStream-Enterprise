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
| A tenant's admins | Issue and revoke connector tokens; publish field rules (signed as the next version, offered to connectors as the **candidate** for shadow evaluation); promote a version to **active**; withdraw a candidate; list connectors and audit-chain heads |
| Connectors | `GET /v1/agent/policy/active` and `/candidate`; `POST /v1/agent/telemetry` |

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

## Develop

```bash
npm ci && npm test
```

Tests run inside workerd, the production runtime, with local D1 and R2. Nothing touches
Cloudflare.

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

- Connectors do not call this API yet; that is the next phase. Until then policies still
  reach them as files.
- No web console: the API is the interface.
- Telemetry is written in the request, not through a queue. At one event per connector per
  minute that is ample; a queue goes in front when volume calls for it.
- Field rules are checked for structure here and in full by the connector, which refuses a
  bundle it cannot use. A misspelt entity type is therefore caught as a rejected candidate,
  not at publish time.
