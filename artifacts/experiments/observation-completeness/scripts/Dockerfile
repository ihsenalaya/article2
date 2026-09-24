# Task 05 observation-completeness test tools: altpath-probe (B2, alternate
# syscall-path bypass testing) and rate-gen (B1, controlled event-rate
# generation). Both pure-stdlib Go, no CGO, so a scratch runtime image works.
FROM golang:1.25 AS builder
WORKDIR /workspace
COPY go.mod go.mod
COPY altpath-probe/main.go altpath-probe/main.go
COPY rate-gen/main.go rate-gen/main.go
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/altpath-probe ./altpath-probe
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/rate-gen ./rate-gen

FROM busybox:1.36
COPY --from=builder /out/altpath-probe /usr/local/bin/altpath-probe
COPY --from=builder /out/rate-gen /usr/local/bin/rate-gen
ENTRYPOINT ["sleep", "3600"]
