# Security Task - RBAC Audit & Monitoring System

A comprehensive Kubernetes RBAC auditing and monitoring system composed of three microservices that track user access, ship audit logs to Elasticsearch, and expose Prometheus metrics.

## Architecture

```
┌─────────────────────┐
│  Kubernetes API     │
│  (RBAC resources)   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐      ┌──────────────────────┐
│   audit-logs/       │─────▶│  shared/             │
│   (rbac-audit)      │      │  - reports.jsonl     │
│                     │      │  - reports-flat.jsonl│
└─────────────────────┘      └──────────┬───────────┘
                                        │
                                        ▼
                             ┌──────────────────────┐
                             │  sidecar/            │
                             │  (rbac-sidecar)      │
                             └──────────┬───────────┘
                                        │
                                        ▼
                             ┌──────────────────────┐
                             │   Elasticsearch      │
                             └──────────┬───────────┘
                                        │
                                        ▼
                             ┌──────────────────────┐
                             │  rbac-exporter/      │
                             │  (Prometheus)        │
                             └──────────────────────┘
```

## Services

### 1. **audit-logs** - RBAC Audit Service
Queries Kubernetes API for RBAC resources and maps them to user principals.

- **Binary**: `rbac-audit`
- **Language**: Go 1.22
- **Input**: `shared/json-files/input.json` (principals list)
- **Output**: `shared/reports.jsonl`, `shared/reports-flat.jsonl`

### 2. **sidecar** - Elasticsearch Shipper
Continuously reads audit logs and ships them to Elasticsearch.

- **Binary**: `rbac-sidecar`
- **Language**: Go 1.22
- **Input**: `shared/reports*.jsonl`
- **Output**: Elasticsearch indices (`audit-logs`, `audit-logs-flat`)

### 3. **rbac-exporter** - Prometheus Metrics Exporter
Queries Elasticsearch and exposes aggregated RBAC metrics.

- **Binary**: `rbac-exporter`
- **Language**: Go 1.23
- **Input**: Elasticsearch
- **Output**: HTTP `/metrics` endpoint (Prometheus format)

## Project Structure

```
security-task
├── audit-logs          # Audit microservice
│   ├── main.go
│   ├── access_mapper.go
│   ├── input_loader.go
│   ├── go.mod
│   └── Dockerfile
├── sidecar             # Elasticsearch shipper
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
├── rbac-exporter       # Prometheus exporter
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
├── shared              # Shared volume (config + runtime data)
│   ├── json-files      # Configuration files
│   │   └── input.json
│   ├── reports.jsonl
│   ├── reports-flat.jsonl
│   ├── .offset
│   └── .offset-flat
└── env-details.md       # Environment variables documentation
```

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


## Quick Start

### for building Services

```bash
# Build audit-logs
cd audit-logs
docker buildx build \
  --platform linux/amd64 \
  -t docker.io/mahdixak/rbac-audit:<TAG> \
  --push .

# Build sidecar
cd ../sidecar
docker buildx build \
  --platform linux/amd64 \
  -t docker.io/mahdixak/rbac-sidecar:<TAG> \
  --push .

# Build rbac-exporter
cd ../rbac-exporter
docker buildx build \
  --platform linux/amd64 \
  -t docker.io/mahdixak/rbac-exporter:<TAG> \
  --push .
  
```

## Configuration

All services are configured via environment variables. See [`env-details.md`](./env-details.md) for complete documentation.

## Metrics

The `rbac-exporter` exposes the following Prometheus metrics:

- `rbac_flat_docs_total`: Total RBAC documents
- `rbac_users_total`: Distinct users count
- `rbac_permission_grants_total`: Permission grants by namespace/resource/verb
- `rbac_exporter_scrape_errors_total`: Scrape errors
- `rbac_exporter_last_success_unixtime`: Last successful refresh timestamp

important metrics:

- `k8s_namespace_sensitive_access_users_count`: Users with sensitive access per namespace
- `k8s_clusterwide_sensitive_access_users_count`: Users with cluster-wide access

---

