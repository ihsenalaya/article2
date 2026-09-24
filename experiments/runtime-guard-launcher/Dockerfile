FROM golang:1.25 AS builder
WORKDIR /workspace
COPY operator/go.mod operator/go.sum ./
RUN go mod download
COPY operator/api/ api/
COPY operator/cmd/runtime-guard-launcher/ cmd/runtime-guard-launcher/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -o runtime-guard-launcher ./cmd/runtime-guard-launcher

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/runtime-guard-launcher /runtime-guard-launcher
ENTRYPOINT ["/runtime-guard-launcher"]
