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

### 1. **audit-logs/** - RBAC Audit Service
Queries Kubernetes API for RBAC resources and maps them to user principals.

- **Binary**: `rbac-audit`
- **Language**: Go 1.22
- **Input**: `shared/json-files/input.json` (principals list)
- **Output**: `shared/reports.jsonl`, `shared/reports-flat.jsonl`

### 2. **sidecar/** - Elasticsearch Shipper
Continuously reads audit logs and ships them to Elasticsearch.

- **Binary**: `rbac-sidecar`
- **Language**: Go 1.22
- **Input**: `shared/reports*.jsonl`
- **Output**: Elasticsearch indices (`audit-logs`, `audit-logs-flat`)

### 3. **rbac-exporter/** - Prometheus Metrics Exporter
Queries Elasticsearch and exposes aggregated RBAC metrics.

- **Binary**: `rbac-exporter`
- **Language**: Go 1.23
- **Input**: Elasticsearch
- **Output**: HTTP `/metrics` endpoint (Prometheus format)

## Project Structure

```
security-task/
├── audit-logs/          # Audit microservice
│   ├── main.go
│   ├── access_mapper.go
│   ├── input_loader.go
│   ├── go.mod
│   └── Dockerfile
├── sidecar/             # Elasticsearch shipper
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
├── rbac-exporter/       # Prometheus exporter
│   ├── main.go
│   ├── go.mod
│   └── Dockerfile
├── shared/              # Shared volume (config + runtime data)
│   ├── json-files/      # Configuration files
│   │   └── input.json
│   ├── reports.jsonl
│   ├── reports-flat.jsonl
│   ├── .offset
│   └── .offset-flat
└── env-details.md       # Environment variables documentation
```

## Quick Start

### Build All Services

```bash
# Build audit-logs
cd audit-logs
docker build -t rbac-audit:latest .

# Build sidecar
cd ../sidecar
docker build -t rbac-sidecar:latest .

# Build rbac-exporter
cd ../rbac-exporter
docker build -t rbac-exporter:latest .
```

### Run with Docker Compose

See `env-details.md` for complete Docker Compose and Kubernetes deployment examples.

## Configuration

All services are configured via environment variables. See [`env-details.md`](./env-details.md) for complete documentation.

### Key Environment Variables

**audit-logs:**
- `INPUT_PATH`: Path to principals configuration (default: `../shared/json-files/input.json`)
- `OUTPUT_JSONL_PATH`: Output path for audit reports (default: `../shared/reports.jsonl`)

**sidecar:**
- `ELASTICSEARCH_URL`: Elasticsearch cluster URL
- `ELASTICSEARCH_DATA_PATH`: Path to read audit logs

**rbac-exporter:**
- `ELASTICSEARCH_URL`: Elasticsearch query endpoint
- `LISTEN_ADDR`: HTTP server address for metrics

## Metrics

The `rbac-exporter` exposes the following Prometheus metrics:

- `rbac_flat_docs_total`: Total RBAC documents
- `rbac_users_total`: Distinct users count
- `rbac_permission_grants_total`: Permission grants by namespace/resource/verb
- `k8s_namespace_sensitive_access_users_count`: Users with sensitive access per namespace
- `k8s_clusterwide_sensitive_access_users_count`: Users with cluster-wide access
- `rbac_exporter_scrape_errors_total`: Scrape errors
- `rbac_exporter_last_success_unixtime`: Last successful refresh timestamp

---

# Code Explanation 

### type Access: 
each access object represent for an access that some app or someone has to something

### kind:
means who has access app, group or user. possible values:
- "User"
- "Group"
- "ServiceAccount"

### name:
name of the subject, depends on what is the value of kind

### namespace:
for users and group are empty and for serviceAccount is the namespace of the service

### namespaces:
tells that this access is namespaced or not

### roleRefKind: 
represent the type of role being referenced. possible values:
- "Role"
- "ClusterRole"

### roleRefName:
role name

### binding:
name of the binding object that grants the access.

### example:
```
kind: RoleBinding
metadata:
  name: view-binding
  namespace: dev
subjects:
- kind: User
  name: alice
roleRef:
  kind: Role
  name: view
```
turns into 
```
Access{
    kind:        "User",
    name:        "alice",
    namespace:   "dev",
    namespaced:  true,
    roleRefKind: "Role",
    roleRefName: "view",
    binding:     "RoleBinding/dev/view-binding",
}
```


