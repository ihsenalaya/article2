#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER:-article2}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-${CLUSTER_NAME}}"

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

echo "==> validating cluster context"
kind get clusters | grep -qx "$CLUSTER_NAME"
kubectl --context "$KUBE_CONTEXT" cluster-info

echo "==> validating nodes"
kubectl --context "$KUBE_CONTEXT" get nodes -o wide
kubectl --context "$KUBE_CONTEXT" wait node --all --for=condition=Ready --timeout=180s

echo "==> validating DNS"
kubectl --context "$KUBE_CONTEXT" -n kube-system get deployment coredns
kubectl --context "$KUBE_CONTEXT" -n kube-system rollout status deployment/coredns --timeout=180s

echo "==> recording storage classes"
kubectl --context "$KUBE_CONTEXT" get storageclass || true

echo "==> validating CRDs"
kubectl --context "$KUBE_CONTEXT" get crd aiplacementdecisions.aiops.imperium.io
kubectl --context "$KUBE_CONTEXT" get crd runtimesecuritypolicies.aiops.imperium.io
kubectl --context "$KUBE_CONTEXT" get crd runtimeplacementevidences.aiops.imperium.io

echo "==> validating operator deployment"
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-operator-system get deployment,pods -o wide
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-operator-system rollout status \
  deployment/runtime-guard-operator-controller-manager --timeout=180s

echo "==> validating agent deployment"
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-agent-system get daemonset,pods -o wide
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-agent-system rollout status \
  daemonset/runtime-guard-agent --timeout=180s

echo "==> kind lab validation complete"
