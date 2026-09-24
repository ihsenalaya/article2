# Build the Runtime Guard node eBPF agent.
#
# IMPORTANT: build with the *repo root* (article2/) as context, not
# ebpf-agent/, since go.mod's local `replace` directive pulls in the sibling
# ../operator module (shared CRD Go types + crypto primitives) which must
# also be in the build context:
#
#   docker build -f ebpf-agent/Dockerfile -t runtime-guard-ebpf-agent:dev .
#
# (run from article2/, i.e. the parent of both ebpf-agent/ and operator/)
#
# Note: this is a plain Go build, no clang/LLVM/libbpf here. The compiled
# eBPF object (internal/bpfobjs/agent_x86_bpfel.o) is generated once on a
# machine with the eBPF toolchain (clang, llvm, libbpf-dev, bpftool — see
# README.md's "Regenerating the eBPF object" section and EXPERIMENTS_LOG.md
# Phase 4 for the exact commands) and committed alongside the bpf2go-generated
# Go bindings that embed it (//go:embed). This is standard practice for
# CO-RE eBPF programs: the object is portable across kernel versions with
# BTF enabled (that portability is the whole point of CO-RE — field offsets
# are resolved against the *target* kernel's BTF at load time, not baked in
# at compile time), so there is no need to recompile C on every target
# platform, and the container build stays a plain, fast, reproducible `go build`.
FROM golang:1.25 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /
COPY operator/ operator/
WORKDIR /workspace
COPY ebpf-agent/go.mod go.mod
COPY ebpf-agent/go.sum go.sum
RUN go mod download

COPY ebpf-agent/cmd/ cmd/
COPY ebpf-agent/internal/ internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -a -o agent ./cmd/agent

# Distroless glibc-free base, consistent with the Operator's Dockerfile.
FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/agent .
USER 0:0
# The agent needs CAP_BPF/CAP_SYS_ADMIN etc. at runtime (granted via the
# DaemonSet's securityContext, not here) and must run as root inside its
# container for those capabilities to apply — "nonroot" in the base image
# name refers to the image's default user, overridden here.

ENTRYPOINT ["/agent"]
