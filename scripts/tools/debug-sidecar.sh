#!/bin/bash
# Troubleshoot why the sidecar is not sending data to Elasticsearch.
# Run from repo root. Requires: kubectl, namespace audit-logs, secret es-credentials.

set -e
NS="${AUDIT_LOGS_NS:-audit-logs}"
ES_URL="${ELASTICSEARCH_URL:-https://elasticsearch.mahdixak.ir}"
ES_URL="${ES_URL%/}"

echo "=== 1. Sidecar logs (last 30 lines) ==="
echo "Look for: sidecar tick, data file not ready, shipOnce error, flush success"
echo ""
POD=$(kubectl get pod -n "$NS" -l app.kubernetes.io/instance=audit-logs -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
if [[ -z "$POD" ]]; then
  echo "No audit-logs pod found in namespace $NS"
  exit 1
fi
kubectl logs -n "$NS" "$POD" -c sidecar --tail=30 2>/dev/null || echo "(no logs)"
echo ""

echo "=== 2. Secret es-credentials exists? ==="
if kubectl get secret -n "$NS" es-credentials -o name &>/dev/null; then
  echo "Secret es-credentials exists."
  kubectl get secret -n "$NS" es-credentials -o jsonpath='{.data}' | tr ',' '\n' | sed 's/.*"\([^"]*\)":.*/\1/' 2>/dev/null | head -5 || true
else
  echo "ERROR: Secret es-credentials NOT found in namespace $NS"
  echo "Create it: kubectl create secret generic es-credentials -n $NS --from-literal=username=... --from-literal=password=..."
fi
echo ""

echo "=== 3. ES connectivity from cluster ==="
echo "Running ephemeral curl pod to test $ES_URL ..."
if kubectl get secret -n "$NS" es-credentials &>/dev/null; then
  kubectl delete pod -n "$NS" debug-es-curl --ignore-not-found --wait=false 2>/dev/null
  sleep 2
  TMP=$(mktemp)
  cat <<EOF >"$TMP"
apiVersion: v1
kind: Pod
metadata:
  name: debug-es-curl
  namespace: $NS
spec:
  restartPolicy: Never
  containers:
  - name: curl
    image: curlimages/curl:latest
    command:
    - sh
    - -c
    - 'curl -s -o /dev/null -w "HTTP %{http_code}\n" -u "$USERNAME:$PASSWORD" '"$ES_URL"' || exit 1'
    env:
    - name: USERNAME
      valueFrom:
        secretKeyRef:
          name: es-credentials
          key: username
    - name: PASSWORD
      valueFrom:
        secretKeyRef:
          name: es-credentials
          key: password
EOF
  kubectl apply -f "$TMP" &>/dev/null
  sleep 5
  kubectl logs -n "$NS" debug-es-curl 2>/dev/null || true
  kubectl delete pod -n "$NS" debug-es-curl --ignore-not-found --wait=false 2>/dev/null &
  rm -f "$TMP"
else
  echo "Skipped (secret es-credentials missing)."
fi
echo ""

echo "=== 4. Checklist ==="
echo "- data file not ready -> audit has not written yet (runs every 5m); wait or check audit container."
echo "- shipOnce error: ensure index -> ES unreachable, auth, or TLS (self-signed cert) issue."
echo "- shipOnce error: bulk request failed -> ES unreachable or timeout."
echo "- flush success -> sidecar is shipping; check ES index docs."