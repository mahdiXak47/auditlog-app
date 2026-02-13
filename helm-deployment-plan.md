# Helm Deployment Plan – Security Audit Stack

Final deployment plan for audit-logs, sidecar, and rbac-exporter on Kubernetes using Helm.

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

### 1.3 RBAC Clarification

- **Existing in cluster (do not create):** ClusterRoles, ClusterRoleBindings, Roles, RoleBindings that define who can do what. audit-logs will **read** these.
- **Create in Helm:** One ServiceAccount, one ClusterRole, one ClusterRoleBinding so the audit-logs pod has **permission to read** those existing RBAC resources.

---

## 2. Helm Chart Layout

```
security-task-chart/
├── Chart.yaml
├── values.yaml
├── values.schema.json          # optional
├── templates/
│   ├── _helpers.tpl
│   ├── configmap.yaml          # input.json (principals)
│   ├── secret.yaml             # ES username/password (or reference existing)
│   ├── serviceaccount.yaml
│   ├── clusterrole.yaml
│   ├── clusterrolebinding.yaml
│   ├── deployment-audit.yaml   # Pod: audit-logs + sidecar
│   ├── service-exporter.yaml  # Service for rbac-exporter
│   ├── deployment-exporter.yaml
│   └── NOTES.txt
└── README.md
```

---

## 3. Resource Specifications

### 3.1 ServiceAccount

- **Name:** Configurable (e.g. `security-audit`).
- **Namespace:** Release namespace.
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

- **Name:** e.g. `security-audit-input`.
- **Content:** `input.json` (principals to audit).
- **Mount:** Into audit pod at e.g. `/shared/json-files/input.json` (or path matching `INPUT_PATH` env).

### 3.5 Secret

- **Name:** e.g. `security-audit-es-credentials`.
- **Data:** `ES_USERNAME`, `ES_PASSWORD` (or keys used by sidecar/exporter).
- **Usage:** Mount as env or envFrom in sidecar and rbac-exporter. Support `existingSecret` in values to use a pre-created secret.

### 3.6 Deployment: Audit + Sidecar (single pod)

- **Name:** e.g. `security-audit`.
- **Replicas:** 1 (shared volume is emptyDir; scaling would require shared storage).
- **Pod:**
  - **serviceAccountName:** ServiceAccount above.
  - **Containers:**
    1. **audit-logs**
       - Image: from values (e.g. `rbac-audit`).
       - Env: `INPUT_PATH`, `OUTPUT_JSONL_PATH`, `OUTPUT_FLAT_JSONL_PATH`, `DEBUG_OUTPUT_PATH` (all under `/shared/...`).
       - Args: e.g. `-interval=5m`.
       - Volume mounts: shared volume, ConfigMap at `/shared/json-files/input.json`.
    2. **sidecar**
       - Image: from values (e.g. `rbac-sidecar`).
       - Env: `ELASTICSEARCH_*`, `ES_USERNAME`, `ES_PASSWORD` (from Secret), paths under `/shared`.
       - Volume mounts: shared volume only.
  - **Volumes:**
    - `shared`: emptyDir.
    - `input`: ConfigMap with input.json (or copy into shared via initContainer if needed).
- **InitContainer (optional):** Copy ConfigMap into `/shared/json-files/` so both paths and permissions are consistent.

### 3.7 Deployment: rbac-exporter

- **Name:** e.g. `rbac-exporter`.
- **Replicas:** From values (e.g. 1).
- **Pod:**
  - **Containers:**
    - **rbac-exporter**
      - Image: from values.
      - Env: `ELASTICSEARCH_URL`, `ES_INDEX`, `ES_USERNAME`, `ES_PASSWORD`, `WINDOW`, `POLL_EVERY`, `LISTEN_ADDR`, etc.
      - Port: 8080.
  - **No** shared volume with audit pod.
- **Service:** ClusterIP (or as needed) for port 8080, used by Prometheus.

### 3.8 Service: rbac-exporter

- **Name:** e.g. `rbac-exporter`.
- **Port:** 8080 (e.g. name `metrics`).
- **Selector:** Labels of rbac-exporter deployment.

### 3.9 Optional: ServiceMonitor (Prometheus Operator)

- If using Prometheus Operator: ServiceMonitor selecting the rbac-exporter Service, scrape port 8080, interval e.g. 30s.

---

## 4. values.yaml Structure (Summary)

- **Global:** imagePullPolicy, image registry.
- **Images:** repository + tag (or digest) for audit-logs, sidecar, rbac-exporter.
- **Elasticsearch:** url, index names; existingSecret or inline username/password.
- **Config:** polling interval for audit-logs; window and poll interval for exporter; input principals (or reference to ConfigMap key).
- **RBAC:** create ServiceAccount/ClusterRole/ClusterRoleBinding or not; names.
- **Resources:** requests/limits for each container.
- **Exporter:** replicas, service type.

---

## 5. Deployment Order (Helm)

Helm will create resources in a dependency-safe order. Suggested order in templates (or controlled by Helm hooks if needed):

1. ConfigMap, Secret (if creating new).
2. ServiceAccount.
3. ClusterRole, ClusterRoleBinding.
4. Deployments (audit+sidecar, exporter).
5. Services.
6. ServiceMonitor (if used).

No need for manual ordering if all are in `templates/` and no explicit dependencies; Helm handles it.

---

## 6. Pre-Deployment Checklist

- [ ] Build and push images: audit-logs, sidecar, rbac-exporter.
- [ ] Prepare `input.json` (principals) for ConfigMap or values.
- [ ] Decide ES credentials: create new Secret or use existing (e.g. `existingSecret: "my-es-secret"`).
- [ ] Ensure cluster can pull images (imagePullSecrets if private registry).
- [ ] Ensure network access from cluster to Elasticsearch (and from Prometheus to rbac-exporter).

---

## 7. Install / Upgrade Commands

```bash
# Install
helm install security-audit ./security-task-chart \
  --namespace security-system \
  --create-namespace \
  -f my-values.yaml

# Upgrade
helm upgrade security-audit ./security-task-chart \
  --namespace security-system \
  -f my-values.yaml

# Dry-run
helm install security-audit ./security-task-chart \
  --namespace security-system \
  -f my-values.yaml --dry-run --debug
```

---

## 8. Verification

- **Pods:** `kubectl get pods -n security-system`
- **RBAC:** `kubectl auth can-i list clusterroles --as=system:serviceaccount:security-system:security-audit` → yes
- **Metrics:** `kubectl port-forward svc/rbac-exporter 8080:8080 -n security-system` then `curl http://localhost:8080/metrics`
- **Logs:** `kubectl logs -n security-system -l app=security-audit -c audit-logs` and `-c sidecar`

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
| Deployment (audit+sidecar) | 1 pod, 2 containers, shared emptyDir |
| Deployment (exporter) | 1+ replicas, no shared volume |
| Service | 1 for rbac-exporter (port 8080) |
| ServiceMonitor | Optional, for Prometheus Operator |

This document is the finalized plan for implementing the Helm chart.
