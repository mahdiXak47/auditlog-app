from library/golang:1.23-alpine as builder

workdir /src

run apk add --no-cache ca-certificates

copy go.mod go.sum ./
run go mod download

copy . .
run CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/rbac-exporter main.go

from gcr.hamdocker.ir/distroless/static:nonroot
workdir /
#copy --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
copy --from=builder /out/rbac-exporter /rbac-exporter


expose 8080
entrypoint ["/rbac-exporter"]
