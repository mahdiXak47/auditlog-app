from library/golang:1.23-alpine as build

WORKDIR /src

run apk add --no-cache ca-certificates

copy go.mod go.sum ./
run go mod download

copy . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/rbac-es-exporter main.go

FROM gcr.hamdocker.ir/distroless/static:nonroot
WORKDIR /
copy --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
copy --from=build /out/rbac-exporter /rbac-exporter


expose 8080
ENTRYPOINT ["/rbac-exporter"]
