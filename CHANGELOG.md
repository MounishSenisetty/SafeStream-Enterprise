# Changelog

Notable changes to SafeStream Enterprise. Versions follow [semantic versioning](https://semver.org).

## Unreleased

### Fixed
- Kafka connector: a watchdog exits the process (code 3) when the main loop stalls. After a
  broker crash, a transactional client call could block indefinitely, past its timeout,
  leaving a connector that consumed nothing until something outside restarted it.
- Kafka connector: a record the clean topic rejects for good (`MSG_SIZE_TOO_LARGE`,
  `INVALID_RECORD`, `INVALID_TIMESTAMP`) is now dead-lettered. Before, the connector exited and
  replayed the same record on every restart, in both delivery modes.
- An unknown `LOG_LEVEL` falls back to `INFO` with a warning instead of a traceback.

### Added
- Control-plane uplink (`SAFESTREAM_CONTROL_URL`, `SAFESTREAM_CONTROL_TOKEN`, off by default).
  The connector pulls signed policies and candidates from the control plane and verifies them
  itself. It pushes its audit events there to anchor the hash chain, outbound HTTPS only. Audit
  events are checked against a content-free allow-list before they leave. A control-plane
  outage never stops redaction. `safestream-control check` tries a configuration. The chart
  takes `control.*`, and its NetworkPolicy opens HTTPS out only when the uplink is enabled.
- Leak canaries (`SAFESTREAM_CANARY_INTERVAL_S`, default 300 s): synthetic PII through the live
  redactor, `safestream_canary_leaks_total`, a `canary` field in audit events, and
  `SAFESTREAM_CANARY_ON_LEAK=stop` (exit code 4).
- Control plane: staged rollout of promoted policies (one connector, a tenth, everyone) that
  halts on a leak canary or a DLQ-rate regression; `GET /v1/rollout`, `/abort`, `/resume`;
  `GET /v1/agent/whoami`. Promotion is now staged unless `{"strategy": "immediate"}`.
- Alerts `SafeStreamCanaryLeak` and `SafeStreamControlPlaneUnreachable`.
- `control-plane/`: the control-plane API as a Cloudflare Worker. Tenants with per-tenant
  signing keys, connector tokens, policy publish/promote/withdraw, policy distribution, and
  audit-event ingest that anchors each hash chain and refuses anything but content-free
  fields.
- `infra/cloudflare`: Terraform for safestreamdata.com (DNSSEC, TLS and HSTS settings, CAA,
  anti-spoofing mail records, firewall and rate-limit rules, Pages, D1 and R2), validated in
  CI and applied by the `Deploy` workflow after approval.
- The public site: a landing page plus this documentation, built with MkDocs.
- Shadow mode: a signed candidate policy (`SAFESTREAM_SHADOW_POLICY_FILE`) is evaluated beside
  the policy in force and compared as counts, in metrics and audit events. Its output is never
  published.
- Audit events are `safestream.audit/v2`: each carries its place in a per-run hash chain.
  `safestream-audit verify` detects altered, removed, reordered or replayed events.
- Signed policy bundles: `safestream-policy keygen/sign/verify`, `SAFESTREAM_POLICY_FILE` and
  `SAFESTREAM_POLICY_PUBLIC_KEYS`. The connector verifies the Ed25519 signature, adopts a newer
  version between batches without a restart, and refuses forged, rolled-back, wrong-tenant or
  invalid bundles while keeping the policy in force. Audit events and metrics report the
  version; the chart takes `policy.*`; `safestream-batch --policy` verifies the same way.
- Helm chart (`deploy/helm/safestream-enterprise`), now the source the plain manifests are
  rendered from. Optional KEDA lag-based autoscaling, alert rules and a Grafana dashboard.
  Published as a signed OCI chart on release.
- `safestream-dlq`: summarise the dead-letter topic and replay it through redaction.
- CI installs the chart on a kind cluster and redacts a record end to end.
- Metrics: batch and per-record duration histograms, consumer lag and assigned partitions.
- `bench/run.py` and `docs/benchmarks.md`: measured throughput per core and end to end.
- Property-based tests for the JSON and XML parsers; an integration test that kills the broker
  mid-stream.
- `LOG_FORMAT=json` for the connector and `safestream-batch`.
- Kubernetes: Namespace enforcing the `restricted` Pod Security Standard, PodDisruptionBudget,
  topology spread across nodes and zones, an explicit rolling-update strategy, and
  Prometheus alert rules (`deploy/kubernetes/prometheus-rules.yaml`).
- `requirements.txt`: hash-pinned lock file; the image installs from it with `--require-hashes`.
- CI: pip-audit on the lock file, a Trivy scan of the image, a 90% coverage floor, a weekly
  scheduled run. Release images are signed with cosign.
- `LICENSE`, `SECURITY.md`, `CODEOWNERS` and this changelog.

### Changed
- Audit event schema is now `safestream.audit/v2` (adds `chain`, `shadow` and `policy`; no
  field was removed).
- New dependency: `cryptography` (Ed25519).
- The field-rules ConfigMap is named `<release name>-field-rules` (was
  `safestream-field-rules`), and the pods roll when the rules change.
- The image moves to Debian 13 and CPython 3.13 (distroless `python3-debian13`). The Debian 12
  runtime image is no longer patched upstream and carried fixable high and critical CVEs.
- GitHub Actions are pinned to commit SHAs.

## 0.3.0 - 2026-11-06

- IBAN fields are redacted as the `iban` entity type.

## 0.2.1 - 2026-11-06

- Moves to safestream-redactor 0.5.
- Keys in the style of `patient_mrn` are redacted.

## 0.2.0 - 2026-11-05

- Custom field rules from a JSON file or ConfigMap.
- Health probes (`/healthz`, `/readyz`) and Prometheus metrics for the Kafka connector.
- Content-free compliance audit events.
- `safestream-batch`: backfill files, directory trees or stdin in constant memory.

## 0.1.0 - 2026-11-04

- Structure-aware JSON and XML redaction on top of safestream-redactor.
- Kafka connector with at-least-once and exactly-once delivery and a dead-letter topic.
- Distroless, non-root image with base images pinned by digest; Kubernetes manifest with a
  default-deny NetworkPolicy.
- CI with real-broker integration tests; release workflow publishing to GHCR.
