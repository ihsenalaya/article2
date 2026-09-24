#!/usr/bin/env bash
set -euo pipefail

CLUSTER_NAME="${KIND_CLUSTER:-article2}"

if ! command -v kind >/dev/null 2>&1; then
  echo "required command not found: kind" >&2
  exit 127
fi
if ! command -v docker >/dev/null 2>&1; then
  echo "required command not found: docker" >&2
  exit 127
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker is installed but not usable from this shell; enable Docker Desktop WSL integration or provide a working Docker daemon" >&2
  exit 1
fi

echo "==> inventory before deleting kind lab"
kind get clusters || true
kubectl config get-contexts || true

if kind get clusters | grep -qx "$CLUSTER_NAME"; then
  kind delete cluster --name "$CLUSTER_NAME"
else
  echo "kind cluster '$CLUSTER_NAME' does not exist; nothing to delete"
fi
