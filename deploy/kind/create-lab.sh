#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

CLUSTER_NAME="${KIND_CLUSTER:-article2}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${CLUSTER_NAME}}"
OPERATOR_IMAGE="${OPERATOR_IMAGE:-runtime-guard-operator:dev}"
AGENT_IMAGE="${AGENT_IMAGE:-runtime-guard-ebpf-agent:dev}"

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "required command not found: $1" >&2
    exit 127
  fi
}

require kind
require kubectl
require docker

if ! docker info >/dev/null 2>&1; then
  echo "docker is installed but not usable from this shell; enable Docker Desktop WSL integration or provide a working Docker daemon" >&2
  exit 1
fi

echo "==> inventory before creating kind lab"
kind get clusters || true
kubectl config get-contexts || true
docker ps || true

if kind get clusters | grep -qx "$CLUSTER_NAME"; then
  echo "==> deleting existing kind cluster '$CLUSTER_NAME' for clean reproducibility"
  kind delete cluster --name "$CLUSTER_NAME"
fi

echo "==> creating kind cluster '$CLUSTER_NAME'"
kind create cluster --name "$CLUSTER_NAME" --config "$SCRIPT_DIR/kind-config.yaml"

echo "==> building local images"
docker build -t "$OPERATOR_IMAGE" "$REPO_ROOT/operator"
docker build -f "$REPO_ROOT/ebpf-agent/Dockerfile" -t "$AGENT_IMAGE" "$REPO_ROOT"

AGENT_IMAGE_ID="$(docker image inspect --format '{{.Id}}' "$AGENT_IMAGE")"
AGENT_IMAGE_DIGEST="${AGENT_IMAGE}@${AGENT_IMAGE_ID}"

echo "==> loading local images into kind"
kind load docker-image "$OPERATOR_IMAGE" --name "$CLUSTER_NAME"
kind load docker-image "$AGENT_IMAGE" --name "$CLUSTER_NAME"

echo "==> waiting for nodes and DNS"
kubectl --context "$KUBE_CONTEXT" wait node --all --for=condition=Ready --timeout=180s
kubectl --context "$KUBE_CONTEXT" -n kube-system rollout status deployment/coredns --timeout=180s

echo "==> applying CRDs and trust anchors"
kubectl --context "$KUBE_CONTEXT" apply -f "$SCRIPT_DIR/upstream-aiplacementdecision-crd.yaml"
KUBE_CONTEXT="$KUBE_CONTEXT" "$SCRIPT_DIR/gen-trust-anchor.sh"
KUBE_CONTEXT="$KUBE_CONTEXT" "$SCRIPT_DIR/gen-agent-key.sh"

echo "==> deploying operator and node agent"
kubectl --context "$KUBE_CONTEXT" apply -k "$REPO_ROOT/operator/config/kind"
kubectl --context "$KUBE_CONTEXT" apply -f "$SCRIPT_DIR/agent-daemonset.yaml"
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-operator-system set env \
  deployment/runtime-guard-operator-controller-manager \
  "AGENT_IMAGE_DIGEST=$AGENT_IMAGE_DIGEST"
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-agent-system set env \
  daemonset/runtime-guard-agent \
  "AGENT_IMAGE_DIGEST=$AGENT_IMAGE_DIGEST"

echo "==> validating kind lab"
KIND_CLUSTER="$CLUSTER_NAME" KUBE_CONTEXT="$KUBE_CONTEXT" "$SCRIPT_DIR/validate-lab.sh"
