# -------- Build stage --------
FROM hub.hamdocker.ir/golang:1.22-alpine AS builder

#WORKDIR /src

# Install CA certs (useful for TLS to API server, registries, etc.)
RUN apk add --no-cache ca-certificates

# Cache deps first
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build a static binary (good for minimal images)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/rbac-audit .

# -------- Runtime stage --------
FROM gcr.hamdocker.ir/distroless/static:nonroot

WORKDIR /

# Copy binary
COPY --from=builder /out/rbac-audit /rbac-audit

# Run as non-root (distroless:nonroot already sets this)
#USER nonroot:nonroot

# Default args (you can override in k8s manifest)
ENTRYPOINT ["/rbac-audit"]
CMD ["-interval=5m"]
