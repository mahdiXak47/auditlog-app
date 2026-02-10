# -------- Build stage --------
FROM hub.hamdocker.ir/golang:1.22-alpine AS builder

WORKDIR /src

# Install CA certs.
RUN apk add --no-cache ca-certificates

# Cache deps first.
COPY go.mod go.sum ./
RUN go mod download

# Copy source.
COPY . .

# Build a static binary.
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o /out/rbac-sidecar .

# -------- Runtime stage --------
FROM gcr.hamdocker.ir/distroless/static:nonroot

WORKDIR /

# Copy binary.
COPY --from=builder /out/rbac-sidecar /rbac-sidecar

ENTRYPOINT ["/rbac-sidecar"]
