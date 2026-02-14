#!/bin/bash
# Create a temporary pod to test DNS resolution from within the cluster.
# Run from repo root. Resolves host from your machine first, then tests from a pod.

set -e
NS="${AUDIT_LOGS_NS:-audit-logs}"
HOST="${DNS_TEST_HOST:-elasticsearch.mahdixak.ir}"
POD_NAME="dns-test-$(date +%s)"

echo "=== Resolve $HOST from your machine (for hostAliases if DNS fails) ==="
IP=""
for cmd in "getent hosts $HOST" "dig +short $HOST"; do
  out=$(eval "$cmd" 2>/dev/null)
  IP=$(echo "$out" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  [[ -n "$IP" ]] && break
done
if [[ -n "$IP" ]]; then
  echo "Resolved: $HOST -> $IP"
else
  echo "Could not resolve from host. Set DNS_TEST_HOST or resolve manually."
fi
echo ""

echo "=== Running DNS test pod in namespace $NS ==="
TMP=$(mktemp)
cat <<EOF >"$TMP"
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  namespace: $NS
spec:
  restartPolicy: Never
  containers:
  - name: dns-test
    image: busybox:1.36
    command:
    - sh
    - -c
    - "echo 'Testing DNS for $HOST'; nslookup $HOST || echo 'DNS lookup FAILED'; cat /etc/resolv.conf; echo 'Done'"
EOF
kubectl apply -f "$TMP" &>/dev/null
sleep 3
kubectl logs -n "$NS" "$POD_NAME" 2>/dev/null || true
kubectl delete pod -n "$NS" "$POD_NAME" --ignore-not-found --wait=false 2>/dev/null &
rm -f "$TMP"
echo ""

if [[ -n "$IP" ]]; then
  echo "=== If DNS failed above, add hostAliases (set elasticsearch.hostIP) ==="
  echo "  helm upgrade audit-logs ./audit-logs-helm --set elasticsearch.hostIP=$IP -n $NS"
fi
