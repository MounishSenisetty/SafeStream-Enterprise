#!/usr/bin/env bash
# End-to-end test of the Helm chart on a Kubernetes cluster (CI uses kind).
# Expects kubectl pointed at a disposable cluster with the image already loaded:
#   kind create cluster && kind load docker-image safestream-enterprise:ci
#   deploy/e2e/run.sh safestream-enterprise ci
# Proves: the chart installs under the "restricted" Pod Security Standard, the
# connector redacts a real record through Kafka in exactly-once mode, and the
# NetworkPolicy admits the monitoring namespace and nobody else.
set -euo pipefail
cd "$(dirname "$0")/.."
repository=${1:?image repository}
tag=${2:?image tag}
kafka() { kubectl -n kafka exec deploy/kafka -- "$@"; }

kubectl apply -f e2e/kafka.yaml
kubectl -n kafka rollout status deploy/kafka --timeout=180s

kubectl create namespace safestream
kubectl label namespace safestream pod-security.kubernetes.io/enforce=restricted
kubectl create namespace monitoring
kubectl -n safestream create secret generic safestream-secrets \
  --from-literal=hmac-key=e2e-test-key-not-a-real-secret

helm install safestream helm/safestream-enterprise --namespace safestream \
  --set image.repository="$repository" --set image.tag="$tag" \
  --set replicaCount=2 \
  --set kafka.securityProtocol=PLAINTEXT --set kafka.sasl.enabled=false \
  --set redaction.delivery=exactly_once \
  --wait --timeout 180s

record='{"LastName":"Smith","msg":"mail bob@corp.example","level":"info"}'
kafka sh -c "echo '$record' | /opt/kafka/bin/kafka-console-producer.sh \
  --bootstrap-server localhost:9092 --topic ingress-logs"
clean=$(kafka /opt/kafka/bin/kafka-console-consumer.sh --bootstrap-server localhost:9092 \
  --topic egress-logs-clean --from-beginning --max-messages 1 --timeout-ms 90000 \
  --isolation-level read_committed)
echo "clean record: $clean"
case "$clean" in
  *Smith* | *bob@corp.example*) echo "FAIL: sensitive data reached the clean topic"; exit 1 ;;
  *'"level":"info"'*) ;;
  *) echo "FAIL: no redacted record on the clean topic"; exit 1 ;;
esac

pod_ip=$(kubectl -n safestream get pods -l app.kubernetes.io/name=safestream-kafka-redactor \
  -o jsonpath='{.items[0].status.podIP}')
scrape() { # namespace -> metrics body, or failure
  kubectl -n "$1" run "scrape-$RANDOM" --rm -i --restart=Never --quiet \
    --image=busybox:1.37 -- wget -q -T 5 -O - "http://$pod_ip:9400/metrics"
}
scrape monitoring | grep -q '^safestream_ready 1$' ||
  { echo "FAIL: monitoring namespace cannot scrape metrics"; exit 1; }
if scrape default >/dev/null 2>&1; then
  echo "FAIL: NetworkPolicy let another namespace reach the metrics port"; exit 1
fi
echo "PASS"
