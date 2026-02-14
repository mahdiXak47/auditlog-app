# Helm Deployment Plan – Security Audit Stack

Final deployment plan for audit-logs, sidecar, and rbac-exporter on Kubernetes using Helm.


## 6. Before using Helm

- [ ] Build and push images: audit-logs, sidecar.
- [ ] Prepare `input.json` (principals) for ConfigMap (`input-reader`).
- [ ] Create `input-reader` ConfigMap in target namespace.
- [ ] Create `es-credentials` Secret in target namespace with `username` and `password` keys.


---

## 1. Target Architecture

### 1.1 Components

| Component | Description | Deployment |
|-----------|-------------|------------|
| **audit-logs** | Reads cluster RBAC, maps to principals, writes JSONL to shared volume | Same pod as sidecar |
| **sidecar** | Reads JSONL from shared volume, bulk-indexes to Elasticsearch | Same pod as audit-logs |
| **rbac-exporter** | Queries Elasticsearch, exposes Prometheus metrics on :8080/metrics | Separate Deployment |

### 1.2 Data Flow

```
Kubernetes API (existing RBAC)
    ↓ read (needs ServiceAccount + ClusterRole + ClusterRoleBinding)
audit-logs
    ↓ write
shared volume (emptyDir): /shared
    ├── json-files/input.json (from ConfigMap)
    ├── reports.jsonl
    └── reports-flat.jsonl
    ↓ read
sidecar
    ↓ bulk index
Elasticsearch (external)

Elasticsearch
    ↓ query
rbac-exporter
    ↓ scrape
Prometheus
```

---

## 2. Helm Chart Layout (as implemented)

```
audit-logs-helm
├── Chart.yaml
├── values.yaml
├── files
│   └── input.json
├── templates
│   ├── _helpers.tpl
│   ├── serviceaccount.yaml
│   ├── clusterrole.yaml
│   ├── clusterrolebinding.yaml
│   ├── configmap-input.yaml    # Optional; config references existingConfigMap
│   ├── deployment-audit.yaml   # Pod: init containers + audit-logs + sidecar
│   └── NOTES.txt
└── (rbac-exporter: separate k8s/exporter-standalone.yaml)
```

---

## 3. Resource Specifications

### 3.1 ServiceAccount

- **Name:** Configurable (e.g. `security-audit`).
- **Namespace:** audit-logs
- **Used by:** Pod that runs audit-logs (and sidecar). Referenced in `deployment-audit.yaml` as `serviceAccountName`.

### 3.2 ClusterRole

- **Name:** e.g. `security-audit-reader`.
- **Purpose:** Define read-only permissions for audit-logs.
- **Rules:**
  - `rbac.authorization.k8s.io`: `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings` → verbs: `get`, `list`, `watch`.
  - `""` (core): `namespaces` → verbs: `get`, `list`.
- **No** create/update/delete/patch.

### 3.3 ClusterRoleBinding

- **Name:** e.g. `security-audit-binding`.
- **roleRef:** ClusterRole above.
- **subjects:** ServiceAccount (name + namespace from release).

### 3.4 ConfigMap

- **Name:** e.g. `input-reader` (in the release namespace).
- **Content:** `input.json` (principals to audit), created **outside** Helm:
  ```bash
  kubectl create configmap input-reader \\
    -n <namespace> \\
    --from-file=input.json=./json-files/input.json
  ```
- **Mount:** Helm mounts this existing ConfigMap into the audit pod at `/shared/json-files/input.json` (matching `INPUT_PATH`).

### 3.5 Secret

- **Name:** e.g. `es-credentials` (in the release namespace).
- **Data:** `username`, `password` (keys used by sidecar/exporter).
- **Creation:** Managed **outside** Helm (not templated), for example:
  ```bash
  kubectl create secret generic es-credentials \\
    -n <namespace> \\
    --from-literal=username=... \\
    --from-literal=password=...
  ```
- **Usage:** Helm reads this Secret via `valueFrom.secretKeyRef` in sidecar and rbac-exporter containers, using:
  - `.Values.elasticsearch.existingSecret`
  - `.Values.elasticsearch.usernameKey`
  - `.Values.elasticsearch.passwordKey`

### 3.6 Deployment: Audit + Sidecar (single pod)

- **Name:** e.g. `audit-logs-audit`.
- **Replicas:** 1 (shared volume is emptyDir; scaling would require shared storage).
- **Pod:**
  - **serviceAccountName:** ServiceAccount above.
  - **hostAliases (optional):** When `elasticsearch.hostIP` is set in values, injects `/etc/hosts` entry for ES host (DNS workaround when cluster DNS fails to resolve).
  - **Init containers:**
    1. **reset-offset** – Clears `/shared/.offset` and `/shared/.offset-flat` on pod start.
    2. **copy-input** – Copies ConfigMap `input.json` into `/shared/json-files/input.json`.
  - **Containers:**
    1. **audit-logs**
       - Image: from values (e.g. `rbac-audit`).
       - Env: `INPUT_PATH`, `OUTPUT_JSONL_PATH`, `OUTPUT_FLAT_JSONL_PATH`, `DEBUG_OUTPUT_PATH` (all under `/shared/...`).
       - Args: e.g. `-interval=5m`.
       - Volume mounts: shared volume.
    2. **sidecar**
       - Image: from values (e.g. `rbac-sidecar`).
       - Env: `ELASTICSEARCH_*`, `ES_USERNAME`, `ES_PASSWORD` (from Secret), paths under `/shared`, `FLUSH_EVERY`, `POLL_EVERY`.
       - Volume mounts: shared volume only.
  - **Volumes:**
    - `shared`: emptyDir.
    - `audit-input`: ConfigMap with input.json (read-only, used by copy-input init container).

### 3.7 Deployment: rbac-exporter (standalone)

- **Location:** `k8s/exporter-standalone.yaml` (deployed separately, not in audit-logs Helm chart).
- **Purpose:** Queries Elasticsearch, exposes Prometheus metrics on `:8080/metrics` (with optional basic auth).

---

## 4. values.yaml Structure (Summary)

- **replicaCount:** for audit pod.
- **image:** repositories/tags/pullPolicy for audit-logs and sidecar.
- **serviceAccount:** `create` flag and name (e.g. `rbac-audit`).
- **rbac:** `create` flag and names for ClusterRole/ClusterRoleBinding.
- **config.auditLogs:** interval, paths (`INPUT_PATH`, outputs, `DEBUG_OUTPUT_PATH`), existing ConfigMap name/key for `input.json`.
- **config.sidecar:** flush size and poll interval.
- **elasticsearch:** URL, index names, existing Secret name + username/password keys. **hostIP** and **hostname** for DNS workaround (hostAliases when cluster DNS fails).
- **resources:** per-container `requests` and `limits` for CPU, memory, and `ephemeral-storage` (e.g. 500m CPU, 1Gi RAM, 512Mi ephemeral storage requested; 2 CPU, 4Gi RAM, 512Mi ephemeral storage limited).

---

## 5. Deployment Order (Helm)

Helm will create resources in a dependency-safe order. Suggested order in templates (or controlled by Helm hooks if needed):

1. ConfigMap (if creating new).
2. ServiceAccount.
3. ClusterRole, ClusterRoleBinding.
4. Deployment (audit+sidecar).

No need for manual ordering if all are in `templates/` and no explicit dependencies; Helm handles it.

---

## 7. Install / Upgrade Commands

```bash
# Install
helm install audit-logs ./audit-logs-helm -n audit-logs --create-namespace -f my-values.yaml

# Upgrade (with DNS workaround if needed)
helm upgrade audit-logs ./audit-logs-helm -n audit-logs --set elasticsearch.hostIP=<IP>

# Dry-run
helm install audit-logs ./audit-logs-helm -n audit-logs -f my-values.yaml --dry-run --debug
```

---

## 8. Verification

- **Pods:** `kubectl get pods -n audit-logs`
- **RBAC:** `kubectl auth can-i list clusterroles --as=system:serviceaccount:audit-logs:rbac-audit` → yes
- **Logs:** `kubectl logs -n audit-logs -l app.kubernetes.io/instance=audit-logs -c audit-logs` and `-c sidecar`
- **Metrics (exporter standalone):** `kubectl port-forward svc/<exporter-svc> 8080:8080 -n <ns>` then `curl http://localhost:8080/metrics`

---

## 9. Summary

| Item | Action |
|------|--------|
| Existing cluster RBAC (73 ClusterRoles, etc.) | Do not create; audit-logs reads them |
| ServiceAccount | Create 1 (identity for audit pod) |
| ClusterRole | Create 1 (read-only RBAC + namespaces) |
| ClusterRoleBinding | Create 1 (bind ClusterRole to ServiceAccount) |
| ConfigMap | Create 1 (input.json) |
| Secret | Create or reference existing (ES credentials) |
| Deployment (audit+sidecar) | 1 pod, 2 init containers, 2 containers, shared emptyDir |
| rbac-exporter | Separate `k8s/exporter-standalone.yaml` |

---