# Environment Variables Documentation

This document lists all environment variables used across the security-task project services.

## Project Structure

```
security-task/
├── audit-logs/          # Audit log microservice
│   ├── main.go
│   ├── access_mapper.go
│   ├── input_loader.go
│   ├── go.mod
│   ├── go.sum
│   └── Dockerfile
├── sidecar/             # Elasticsearch shipper microservice
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   └── Dockerfile
├── rbac-exporter/       # Prometheus metrics exporter microservice
│   ├── main.go
│   ├── go.mod
│   ├── go.sum
│   └── Dockerfile
└── shared/              # Shared data volume (mounted by audit-logs and sidecar)
    ├── json-files/      # Configuration and output files
    │   ├── input.json
    │   ├── output.json
    │   └── output-of-the-code.json
    ├── reports.jsonl
    ├── reports-flat.jsonl
    ├── .offset
    └── .offset-flat
```

## Table of Contents
- [Audit Log Service (audit-logs/)](#audit-log-service)
- [Sidecar Service (sidecar/)](#sidecar-service)
- [RBAC Exporter Service (rbac-exporter/)](#rbac-exporter-service)

---

## Audit Log Service

**Binary**: `rbac-audit`  
**Source Directory**: `audit-logs/`  
**Main File**: `audit-logs/main.go`

| Variable | Default Value | Type | Description |
|----------|--------------|------|-------------|
| `INPUT_PATH` | `../shared/json-files/input.json` | string | Path to the input configuration file containing principals (users/groups) to audit. |
| `OUTPUT_JSONL_PATH` | `../shared/reports.jsonl` | string | Path to write nested JSONL audit reports (UserAccessReport format). |
| `OUTPUT_FLAT_JSONL_PATH` | `../shared/reports-flat.jsonl` | string | Path to write flattened JSONL audit reports (FlatPermission format). |
| `DEBUG_OUTPUT_PATH` | `../shared/json-files/output-of-the-code.json` | string | Path to write formatted JSON debug output (pretty-printed reports). |

### Notes
- The audit service reads RBAC data from Kubernetes API and maps it to principals from `INPUT_PATH`.
- Output files are appended to on each run (no rotation built-in).
- Shared directory (`./shared/`) is mounted as a shared volume containing both config files and runtime data.

---

## Sidecar Service

**Binary**: `rbac-sidecar`  
**Source Directory**: `sidecar/`  
**Main File**: `sidecar/main.go`

| Variable | Default Value | Type | Description |
|----------|--------------|------|-------------|
| `ELASTICSEARCH_URL` | `https://mahdixak-security-auditdb.darkube.app/` | string | Elasticsearch cluster URL. |
| `ELASTICSEARCH_INDEX` | `audit-logs` | string | Index name for nested audit reports. |
| `ELASTICSEARCH_FLAT_INDEX` | `audit-logs-flat` | string | Index name for flattened audit reports. |
| `ELASTICSEARCH_DATA_PATH` | `../shared/reports.jsonl` | string | Path to read nested audit reports from (must match audit service output). |
| `ELASTICSEARCH_FLAT_DATA_PATH` | `../shared/reports-flat.jsonl` | string | Path to read flattened audit reports from (must match audit service output). |
| `ELASTICSEARCH_OFFSET_PATH` | `../shared/.offset` | string | File to track read offset for nested reports (for idempotent reads). |
| `ELASTICSEARCH_FLAT_OFFSET_PATH` | `../shared/.offset-flat` | string | File to track read offset for flattened reports (for idempotent reads). |
| `ES_USERNAME` | _(empty)_ | string | Elasticsearch basic auth username (optional). |
| `ES_PASSWORD` | _(empty)_ | string | Elasticsearch basic auth password (optional). |
| `FLUSH_EVERY` | `10` | int | Number of documents to batch before flushing to Elasticsearch. |
| `POLL_EVERY` | `1s` | duration | Interval to poll the JSONL files for new data. |

### Notes
- Sidecar continuously reads from JSONL files and ships data to Elasticsearch.
- Uses content hash (`sha256`) as document `_id` for idempotency.
- On file truncation/rotation, offset resets to 0.
- Creates indices automatically if they don't exist.

---

## RBAC Exporter Service

**Binary**: `rbac-exporter`  
**Source Directory**: `rbac-exporter/`  
**Main File**: `rbac-exporter/main.go`

| Variable | Default Value | Type | Description |
|----------|--------------|------|-------------|
| `ELASTICSEARCH_URL` | `http://localhost:9200` | string | Elasticsearch cluster URL to query audit data from. |
| `ES_INDEX` | `audit-logs-flat` | string | Index name to query for flat audit reports. |
| `ES_USERNAME` | _(empty)_ | string | Elasticsearch basic auth username (optional). |
| `ES_PASSWORD` | _(empty)_ | string | Elasticsearch basic auth password (optional). |
| `WINDOW` | `24h` | duration | Time window to query audit data (e.g., last 24 hours). |
| `POLL_EVERY` | `30s` | duration | Interval to refresh metrics from Elasticsearch. |
| `MAX_BUCKETS` | `10` | int | Maximum number of buckets for Elasticsearch aggregations (terms size). |
| `LISTEN_ADDR` | `:8080` | string | HTTP server address to expose Prometheus metrics endpoint. |

### Exposed Metrics Endpoint
- **URL**: `http://<host>:8080/metrics`
- **Format**: Prometheus text format

### Notes
- Reads from Elasticsearch only (no direct Kubernetes or file access).
- Computes aggregated metrics and exposes them for Prometheus scraping.
- Metrics are reset on each refresh to avoid stale label sets.

---

## Metrics Exposed by RBAC Exporter

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `rbac_flat_docs_total` | Gauge | - | Total number of flat RBAC documents in the time window. |
| `rbac_users_total` | Gauge | - | Number of distinct users seen in the time window. |
| `rbac_permission_grants_total` | GaugeVec | `namespace`, `resource`, `verb`, `scope` | Count of permission grants by dimensions. |
| `rbac_high_risk_grants_total` | GaugeVec | `namespace`, `resource`, `verb`, `scope` | Count of high-risk permissions (create/update/patch/delete). |
| `k8s_namespace_sensitive_access_users_count` | GaugeVec | `namespace`, `verb`, `resource` | Count of distinct users with access to sensitive resources (secrets, deployments, configmaps) per namespace. |
| `k8s_clusterwide_sensitive_access_users_count` | GaugeVec | `resource`, `verb` | Count of distinct users with cluster-wide access to important resources. |
| `rbac_exporter_scrape_errors_total` | Counter | - | Total number of errors during metric collection. |
| `rbac_exporter_last_success_unixtime` | Gauge | - | Unix timestamp of last successful metrics refresh. |

---

## Service Integration Flow

```
┌─────────────────────┐
│  Kubernetes API     │
│  (RBAC resources)   │
└──────────┬──────────┘
           │
           │ (poll)
           ▼
┌─────────────────────┐      ┌──────────────────────┐
│   Audit Service     │─────▶│  shared/ volume      │
│   (rbac-audit)      │      │  - reports.jsonl     │
│                     │      │  - reports-flat.jsonl│
│ Reads: INPUT_PATH   │      │  - .offset           │
│ Writes: shared/     │      │  - .offset-flat      │
└─────────────────────┘      └──────────┬───────────┘
                                        │
                                        │ (poll & read)
                                        ▼
                             ┌──────────────────────┐
                             │  Sidecar Service     │
                             │  (rbac-sidecar)      │
                             │                      │
                             │ Reads: shared/       │
                             │ Writes: Elasticsearch│
                             └──────────┬───────────┘
                                        │
                                        │ (bulk index)
                                        ▼
                             ┌──────────────────────┐
                             │   Elasticsearch      │
                             │   (audit-logs*)      │
                             └──────────┬───────────┘
                                        │
                                        │ (query)
                                        ▼
                             ┌──────────────────────┐
                             │  RBAC Exporter       │
                             │  (rbac-exporter)     │
                             │                      │
                             │ Reads: Elasticsearch │
                             │ Exposes: /metrics    │
                             └──────────┬───────────┘
                                        │
                                        │ (scrape)
                                        ▼
                             ┌──────────────────────┐
                             │    Prometheus        │
                             └──────────────────────┘
```

---

## Deployment Considerations

### Shared Volume
- Audit service and Sidecar must share a volume mounted at `./shared/` (or configure paths accordingly).
- Typical Kubernetes pattern: Pod with two containers and a shared `emptyDir` volume.

### Elasticsearch Access
- Sidecar writes to Elasticsearch (requires write permissions).
- RBAC Exporter reads from Elasticsearch (requires read permissions).
- Both can use `ES_USERNAME` and `ES_PASSWORD` for authentication.

### Input Configuration
- `INPUT_PATH` should be mounted as ConfigMap or Secret in production (not baked into image).
- Contains principals (users/groups) to audit from external source (e.g., SSO, LDAP).

---

## Example Configuration

### Docker Compose
```yaml
version: '3.8'
services:
  audit:
    build:
      context: ./audit-logs
      dockerfile: Dockerfile
    image: rbac-audit:latest
    environment:
      INPUT_PATH: /shared/json-files/input.json
      OUTPUT_JSONL_PATH: /shared/reports.jsonl
      OUTPUT_FLAT_JSONL_PATH: /shared/reports-flat.jsonl
      DEBUG_OUTPUT_PATH: /shared/json-files/output-of-the-code.json
    volumes:
      - shared-data:/shared
    command: ["-interval=5m"]

  sidecar:
    build:
      context: ./sidecar
      dockerfile: Dockerfile
    image: rbac-sidecar:latest
    environment:
      ELASTICSEARCH_URL: https://elasticsearch.example.com
      ELASTICSEARCH_DATA_PATH: /shared/reports.jsonl
      ELASTICSEARCH_FLAT_DATA_PATH: /shared/reports-flat.jsonl
      ELASTICSEARCH_OFFSET_PATH: /shared/.offset
      ELASTICSEARCH_FLAT_OFFSET_PATH: /shared/.offset-flat
      ES_USERNAME: elastic
      ES_PASSWORD: changeme
      FLUSH_EVERY: 50
      POLL_EVERY: 5s
    volumes:
      - shared-data:/shared
    depends_on:
      - audit

  exporter:
    build:
      context: ./rbac-exporter
      dockerfile: Dockerfile
    image: rbac-exporter:latest
    environment:
      ELASTICSEARCH_URL: https://elasticsearch.example.com
      ES_USERNAME: elastic
      ES_PASSWORD: changeme
      WINDOW: 48h
      POLL_EVERY: 60s
      MAX_BUCKETS: 20
    ports:
      - "8080:8080"

volumes:
  shared-data:
```

### Kubernetes Deployment
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: rbac-audit-pod
spec:
  containers:
  - name: audit
    image: rbac-audit:latest
    env:
    - name: INPUT_PATH
      value: /shared/json-files/input.json
    - name: OUTPUT_JSONL_PATH
      value: /shared/reports.jsonl
    volumeMounts:
    - name: shared
      mountPath: /shared

  - name: sidecar
    image: rbac-sidecar:latest
    env:
    - name: ELASTICSEARCH_URL
      value: https://elasticsearch.example.com
    - name: ES_USERNAME
      valueFrom:
        secretKeyRef:
          name: es-creds
          key: username
    - name: ES_PASSWORD
      valueFrom:
        secretKeyRef:
          name: es-creds
          key: password
    volumeMounts:
    - name: shared
      mountPath: /shared

  volumes:
  - name: shared
    emptyDir: {}
  
  # Note: Mount input.json as ConfigMap into shared/json-files/ 
  # initContainers can be used to copy ConfigMap data into shared volume
```
