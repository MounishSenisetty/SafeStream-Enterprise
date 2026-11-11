# SafeStream Enterprise: plan to an enterprise-ready product on safestreamdata.com

## Context

SafeStream Enterprise today is a well-built **self-hosted data plane**: a Kafka consumer group
that redacts JSON/XML records in flight, a batch backfill CLI, a hardened image and a Kubernetes
manifest. What it lacks is everything *around* the data plane that an enterprise buyer expects:
central policy management, fleet visibility, provable audit evidence, packaging, published
performance, and a public home.

Decisions you made (this session):

| Question | Answer |
|---|---|
| What lives on the domain | **Hosted control plane**; the data plane stays in the customer's network |
| Domain | **safestreamdata.com** (Cloudflare) |
| First users | **Design partners, no billing** (multi-tenant, SSO, hand-issued enrollment) |
| Throughput | **Measure first**; scale by partitions; no rewrite unless numbers demand it |

## 1. Findings: where the codebase stands

**Architecture as built** (`src/safestream_enterprise/`, ~900 statements, 93% covered):

- `parsers/json_ast.py`, `parsers/xml_ast.py`: `StructuredRedactor` — field-rule pass plus
  free-text pass through the OSS `safestream-redactor` engine; fail-closed; exposes
  `rule_count` and `rules_fingerprint`.
- `rules.py`: `FieldRulesFile` (pydantic), `load_field_rules`, `make_redactor` — the single
  factory both entry points use, so stream and batch give identical pseudonyms.
- `connectors/kafka.py`: `ConnectorConfig.from_env`, `KafkaRedactionConnector` — at-least-once
  and exactly-once (one transaction per batch), DLQ, poison-pill dead-lettering, content-free
  audit events (`safestream.audit/v1`).
- `connectors/health.py`: `/healthz`, `/readyz`, `/metrics` on the stdlib (counters and two gauges).
- `batch.py`: `safestream-batch`, constant memory, atomic writes, content-free report.
- `logs.py`: `LOG_LEVEL` / `LOG_FORMAT=json`.
- Delivery: distroless Debian 13 image from a hash-locked `requirements.txt`; `deploy/kubernetes/`
  (Namespace/PSA, Deployment, PDB, NetworkPolicy, PrometheusRule); CI with real-Kafka
  integration tests, pip-audit, Trivy, kubeconform; cosign-signed releases.

**Gaps to enterprise grade**

| Area | Gap |
|---|---|
| Security | Field rules are an unsigned file; anyone who can edit the ConfigMap can silently weaken redaction. One static HMAC key, no rotation story. No tenant or identity concept anywhere. Audit events are unsigned and unchained, so they can be dropped or edited after the fact. |
| Scalability | Fixed `replicas: 3`; no lag-based autoscaling. Single-threaded Python consumer per pod with **no published throughput number**, so capacity planning is guesswork. No consumer-lag or latency metric. |
| Observability | Counters only: no latency/batch-duration histograms, no lag, no dashboards, no tracing, no SLOs. Each pod is an island; nothing shows the fleet. |
| Test coverage | Good unit and broker integration tests. Missing: property/fuzz tests on the parsers (the security boundary), fault-injection (broker restart mid-transaction), performance regression gate, a Kubernetes end-to-end test. |
| Resilience | Rule changes need a rolling restart. No DLQ replay tool (records go in, nothing brings them back). No tested upgrade/rollback path. |
| Product | Raw manifest only (no Helm chart). No docs site. JSON/XML only — no Avro/Protobuf/Schema Registry (see open questions). No control plane, onboarding or licensing. |

## 2. Architecture: a zero-content control plane

The standard move would be a SaaS proxy that customers send data to. That breaks the product's
one promise. The proposed design keeps it and makes it *provable*:

```
 customer network (data plane)                    Cloudflare edge: safestreamdata.com (control plane)
 ┌───────────────────────────────────┐            ┌──────────────────────────────────────────────┐
 │ Kafka ─▶ SafeStream agents ─▶ Kafka│  HTTPS,    │ WAF + rate limits + API Shield (mTLS, schema)│
 │            │  ▲                   │  outbound  │   api.  → Worker (Hono/TS)                    │
 │            │  └ signed policy  ◀──┼────────────┼──      D1: tenants, agents, policies, rollouts│
 │            └─ counts + hashes  ───┼───────────▶│        R2: policy bundles, audit evidence     │
 │   record content never leaves     │  only      │        Queues: telemetry ingest               │
 └───────────────────────────────────┘            │   app.  → console (Pages) behind Access SSO   │
                                                  │   www/docs → Pages, cached at the edge        │
                                                  └──────────────────────────────────────────────┘
```

**Invariant, enforced in code and tests:** the agent's uplink schema has no field that can hold
record content — only counts, entity-type names, versions and hashes (the shape
`audit_event()` already produces). A contract test fails the build if a free-text field is added.
The agent only makes outbound requests; the control plane can never reach into a customer cluster.
Control-plane use is optional: with it off, the product runs fully air-gapped exactly as today.

**What makes it different**

1. **Signed policy bundles.** Field rules become a versioned bundle signed with Ed25519. The
   agent verifies signature, tenant and a monotonic version before use; a bad or older bundle is
   refused and the last good one stays in force. Editing a ConfigMap can no longer weaken redaction.
   Bundles are immutable and content-addressed, so the edge caches them forever.
2. **Shadow mode.** A candidate bundle runs beside the active one on live traffic. Only the
   active result is published; the agent reports the *difference in counts* per entity type.
   The console shows "this change would redact 4,100 more `person` values and 0 fewer of anything"
   before anyone promotes it. Nobody else shows the blast radius of a DLP rule change without
   seeing the data.
3. **Tamper-evident audit evidence.** `safestream.audit/v2` adds a sequence number and the hash
   of the previous event per instance; the control plane anchors chain heads in R2 with object
   lock. An auditor verifies a period offline with `safestream-audit verify`: no gaps, no edits.
4. **Leak canaries.** The agent periodically injects synthetic records carrying known fake PII
   into ingress and checks they come out of egress redacted. `safestream_canary_leaks_total`
   staying at zero is continuous end-to-end proof, not a config claim.
5. **Staged policy rollout.** A new bundle goes to one agent, then 10%, then all, and halts
   automatically if DLQ rate or canary results regress.

**Scalability (measure first).** Add a reproducible benchmark and publish records/s per core.
Scale horizontally by partition with KEDA on consumer lag. Control plane is stateless Workers;
telemetry goes through Queues so ingest spikes never block agents. Only if the benchmark shows a
gap do we move hot paths (the OSS engine already has an optional Rust core).

## 3. Cloudflare infrastructure (all Terraform, `infra/cloudflare/`)

| Concern | Design |
|---|---|
| DNS | Zone `safestreamdata.com`, DNSSEC on, CAA limited to Cloudflare's CAs. `www`/apex and `docs.` → Pages; `app.` → console (Pages); `api.` → Worker; `demo.` → Tunnel; `status.` → status page. |
| TLS | Full (strict), TLS 1.2 minimum, HSTS with preload, Always Use HTTPS. |
| Email | SPF, DKIM, DMARC `p=reject`; Email Routing for `security@` so nobody can spoof the domain. |
| WAF | Cloudflare managed ruleset + OWASP core on all hosts. `api.`: deny by default except the published routes, per-agent and per-IP rate limits, body-size cap. |
| API Shield | mTLS client certificates for agents (one per enrolled agent, revocable); request schema validation from the control plane's OpenAPI document. |
| Zero Trust | Access in front of `app.` (each design partner's IdP via OIDC/SAML) and in front of internal admin routes. No passwords stored by us. |
| Caching | Policy bundles: `Cache-Control: immutable`, cached at the edge by hash. Docs/marketing: static, fully cached. API reads: no cache. |
| Tunnel | `demo.safestreamdata.com` → a private demo cluster (Kafka + agents + Grafana) through `cloudflared`; no public ingress on the cluster. Also documented as the supported way for customers to expose their own Grafana. |
| Data | D1 (relational state, point-in-time restore), R2 (bundles, audit evidence with object lock, Logpush target), Queues (telemetry ingest), Workers secrets (signing keys). |
| Environments | `staging` and `production` as separate Worker environments and D1/R2 instances; staging on `*.staging.safestreamdata.com`. |

Needs confirming: API Shield mTLS, some WAF rate-limit features and Logpush depend on the
Cloudflare plan tier (see open questions). Fallback if unavailable: agent-signed JWTs verified
in the Worker instead of edge mTLS.

## 4. CI/CD, testing, observability

**CI/CD** (extends `.github/workflows/ci.yml` and `release.yml`; path-filtered so each part
only runs when touched):

- Data plane: as today (ruff, strict mypy, unit matrix, real-Kafka integration, pip-audit, Trivy,
  kubeconform) plus Helm lint/render, a `kind` end-to-end job, and a benchmark regression gate.
- Control plane: typecheck, lint, Vitest in the Workers runtime, OpenAPI contract check; preview
  deploy per PR, staging on `main`, production on a version tag behind a GitHub environment approval.
- Infra: `terraform plan` on PRs, `apply` on `main` behind approval; state in R2.
- Releases: one tag publishes the signed image, the Helm chart (OCI, signed) and the control plane.

**Testing pyramid**

| Layer | What | Tooling |
|---|---|---|
| Property / fuzz | Seeded PII never appears in any output; output always parses; redaction is idempotent | Hypothesis on `StructuredRedactor` |
| Unit | Existing suite, 90% floor kept | pytest |
| Integration | Existing real-Kafka suite + broker restart mid-transaction (no loss, no duplicate) | pytest + apache/kafka |
| Contract | Agent uplink schema is content-free; agent and Worker agree on OpenAPI | schema tests on both sides |
| End-to-end | Helm install on `kind`, produce PII, assert clean topic and metrics | kind + pytest |
| Performance | records/s per core, p99 batch latency; fail on >10% regression | `bench/` harness |
| Control plane | Tenant isolation, signature checks, rollout state machine | Vitest (Workers pool) |
| Security | Authz matrix tests (tenant A cannot read tenant B), ZAP baseline against staging | CI job |

**Observability**

- Data plane: add histograms (batch duration, per-record redaction time), consumer lag, policy
  version and canary gauges to `connectors/health.py`; ship a Grafana dashboard and extend
  `deploy/kubernetes/prometheus-rules.yaml`. Optional OpenTelemetry traces per batch (no payloads).
- Control plane: structured Workers logs, Analytics Engine for request and fleet metrics,
  Logpush to R2, Cloudflare health checks on `api.` and `app.`.
- SLOs: control-plane API availability 99.9%; policy propagation p99 under 60 s; zero canary
  leaks. Burn-rate alerts for each.

## 5. Phased implementation

Each phase is one or a few PRs, independently shippable, with its own verification.

| # | Phase | Deliverables | Verified by |
|---|---|---|---|
| 0 | Plan in repo (done) | `plan.md` committed at the root | file on `main` |
| 1 | Measure and prove the data plane (done; results in `docs/benchmarks.md`) | `bench/` harness and published numbers; latency histograms and lag metric; Hypothesis tests for both parsers; broker-restart integration test | CI green; benchmark report in `docs/` |
| 2 | Operability (done) | `safestream-dlq replay` CLI; Helm chart in `deploy/helm/` (existing manifest becomes its rendered output, checked in CI); KEDA lag autoscaling; Grafana dashboard | `helm lint`, kubeconform, kind e2e job |
| 3 | Signed policy bundles (done) | Bundle format and `safestream-policy sign/verify`; agent verifies and hot-swaps between batches; last-known-good fallback; bundle version in metrics and audit events. Reuses `FieldRulesFile` and `rules_fingerprint` | unit tests for every refusal path; integration test swapping policy under load with no restart |
| 4 | Shadow mode and audit chain (done) | Candidate bundle evaluated in shadow with count diffs; `safestream.audit/v2` hash chain; `safestream-audit verify` | tests: shadow never changes output; a deleted or edited event fails verification |
| 5 | Cloudflare foundation (code done; first apply needs the account secrets, see `infra/cloudflare/README.md`; Access moves to Phase 8 with the console it protects) | Terraform for zone, DNSSEC, TLS, email records, WAF, Access, R2, D1, staging/production; docs and marketing site on Pages | `terraform plan` clean; SSL Labs A+; DMARC and DNSSEC checks pass; site live |
| 6 | Control plane API | Worker: tenants, agent enrollment, policy publish/fetch, telemetry ingest via Queues, OpenAPI document | Vitest incl. tenant-isolation matrix; staging deploy; schema validation at the edge |
| 7 | Agent uplink | Optional control client in the connector (outbound only, off by default); enrollment; heartbeat and audit forwarding; NetworkPolicy and chart values; leak canaries; staged rollout | contract test for content-free uplink; e2e: publish policy in staging, agent on kind picks it up; air-gapped mode unchanged |
| 8 | Console | `app.` behind Access: fleet health, policy editor with shadow diff, rollout control, audit evidence export | Playwright e2e against staging |
| 9 | Launch readiness | Demo environment behind Tunnel; status page; runbooks; backup/restore drill for D1 and R2; load test of the control plane; security review and ZAP run | drill and load-test reports; checklist signed off |

Phases 1–4 need nothing from Cloudflare and deliver value to a fully self-hosted customer.
Phase 5 can run in parallel with them once you provide a scoped API token.

**Repo layout after the plan** (existing paths unchanged):

```
src/safestream_enterprise/        data plane (+ policy.py, control.py, audit chain)
bench/                            benchmark harness
deploy/helm/  deploy/kubernetes/  chart; rendered manifest; alert rules; dashboard
control-plane/                    Cloudflare Worker (TypeScript), OpenAPI, migrations
docs/  overrides/  mkdocs.yml     docs + marketing site (Pages)
infra/cloudflare/                 Terraform
```

## 6. Open questions

1. **Formats.** Do your design partners' topics carry Avro or Protobuf with a Schema Registry?
   If yes, that support moves ahead of the control plane; JSON/XML-only will block those pilots.
2. **Cloudflare plan tier.** Free, Pro, Business or Enterprise? It decides edge mTLS, advanced
   rate limiting and Logpush versus the in-Worker fallbacks.
3. **Who holds the policy signing key?** Simplest: the control plane signs per tenant.
   Strongest: the customer signs and we only distribute. I recommend starting with the first and
   designing the format for the second.
4. **Pseudonym key rotation.** Rotating the HMAC key breaks joins with older data. Is rotation a
   requirement for your partners, and if so is re-keying history via `safestream-batch` acceptable?
5. **Where do customers run it?** EKS/GKE/AKS, and MSK/Confluent Cloud/self-run Kafka? This sets
   the e2e matrix and the auth mechanisms to document (IAM, OAuth, mTLS).
6. **OSS engine.** May this plan change `safestream-redactor` itself (for example for shadow
   evaluation or performance), or must everything live in this repo?
7. **Compliance target for the control plane.** Is SOC 2 for safestreamdata.com on the roadmap?
   It affects logging retention, access reviews and change management from Phase 5 on.
8. **Licensing.** Should agents enforce a license (signed entitlement checked offline), or is
   that deferred until billing?

## Verification of the plan as a whole

After each phase: `ruff check . && ruff format --check . && mypy && pytest --cov --cov-fail-under=90`,
the real-Kafka integration suite, and the phase's own check from the table. End state is proven by
one scripted demo: enroll a fresh agent on `kind` against staging, publish a policy in the console,
watch it roll out in shadow then live, see zero canary leaks, and verify the period's audit chain
offline.
