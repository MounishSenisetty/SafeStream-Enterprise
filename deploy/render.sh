#!/usr/bin/env bash
# Renders the plain manifests in deploy/kubernetes/ from the Helm chart, for
# clusters that deploy with kubectl. CI fails if they are out of date.
#   deploy/render.sh              (needs helm; set HELM to override the binary)
set -euo pipefail
cd "$(dirname "$0")"
helm=${HELM:-helm}
chart=helm/safestream-enterprise
header='# Rendered from deploy/helm/safestream-enterprise by deploy/render.sh. Do not edit:
# change the chart (or its values) and render again.'

{
  echo "$header"
  cat <<'USAGE'
#
#   kubectl create namespace safestream   # first, so the Secret has somewhere to go
#   kubectl -n safestream create secret generic safestream-secrets \
#     --from-literal=hmac-key="$(openssl rand -hex 32)" \
#     --from-literal=sasl-username=svc-safestream \
#     --from-literal=sasl-password='...'
#   kubectl apply -f deploy/kubernetes/kafka-redactor.yaml
#
# Assumes the brokers run in namespace "kafka" with pod label
# app.kubernetes.io/name=kafka, listening on 9092 with SASL_SSL. For anything
# else, install the chart with your own values instead.
USAGE
  $helm template safestream "$chart" --namespace safestream --set namespace.create=true
} > kubernetes/kafka-redactor.yaml

{
  echo "$header"
  echo "# Optional: apply it only where the PrometheusRule CRD is installed."
  $helm template safestream "$chart" --namespace safestream \
    --set prometheusRule.enabled=true --show-only templates/prometheusrule.yaml
} > kubernetes/prometheus-rules.yaml
