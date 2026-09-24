#!/usr/bin/env bash
# Mints a signed AIPlacementDecision for llm-inference-real (same mechanism
# as mint-test-decision), then PATCHES the resulting RuntimeSecurityPolicy
# with a REAL allowlist -- unlike every other policy minted this mission
# (kind AND both GPU environments), which were all bare deny-all. The
# operator only sets enforcementMode/defaultAction ONCE, on first creation,
# and never overwrites fields on later reconciles (see
# AIPlacementDecisionReconciler doc comment) -- so patching after creation
# is safe and won't be silently reverted.
#
# Exact allowedPaths/allowedPathPrefixes below are a FIRST DRAFT, not
# verified against the real container image yet (see EXPERIMENTS_LOG.md
# Phase 9-ter) -- refine using the agent's own real denial counters/logs
# after first deploying llm-inference-real, rather than guessing further
# in the abstract. Re-run this script (idempotent) after edits.
#
# Usage: KUBE_CONTEXT=cgpu-vm ./mint-allowlist-decision.sh <pod-name> <pod-uid>
set -euo pipefail

POD_NAME="${1:?pod name required}"
POD_UID="${2:?pod UID required}"
KUBE_CONTEXT="${KUBE_CONTEXT:-cgpu-vm}"
NAMESPACE="${NAMESPACE:-workloads}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"

source "$REPO_ROOT/deploy/kind/trust-anchor-cgpu-vm.env"
export TRUST_ANCHOR_PRIVATE_KEY_HEX

(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision --ttl 6h \
  --name "$POD_NAME" --namespace "$NAMESPACE" --target-name "$POD_NAME" \
  --pod-uid "$POD_UID" --node-identity cgpu-vm \
  --priv-key-hex "$TRUST_ANCHOR_PRIVATE_KEY_HEX") \
  | kubectl --context "$KUBE_CONTEXT" apply -f -
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch aiplacementdecision "$POD_NAME" \
  --subresource=status --type=merge -p '{"status":{"decision":"allow"}}'

echo "Waiting for RuntimeSecurityPolicy to be created..."
for i in $(seq 1 15); do
  if kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$POD_NAME" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo "Patching real allowlist into RuntimeSecurityPolicy/$POD_NAME..."
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch runtimesecuritypolicy "$POD_NAME" --type=merge -p '{
  "spec": {
    "exec": {
      "defaultAction": "deny",
      "allowedPaths": [
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/python3",
        "/usr/bin/python3.11",
        "/usr/local/bin/python3",
        "/usr/local/bin/python3.11"
      ]
    },
    "fileAccess": {
      "defaultAction": "deny",
      "allowedPathPrefixes": [
        "/models",
        "/usr",
        "/opt",
        "/lib",
        "/lib64",
        "/etc/ld.so",
        "/tmp",
        "/proc",
        "/dev/shm",
        "/root/.cache"
      ]
    },
    "networkEgress": {
      "defaultAction": "deny",
      "allowedCIDRs": ["127.0.0.1/32"],
      "allowedPorts": [8000]
    },
    "deviceAccess": {
      "defaultAction": "deny",
      "allowedDevicePaths": [
        "/dev/nvidia0",
        "/dev/nvidiactl",
        "/dev/nvidia-uvm",
        "/dev/nvidia-uvm-tools",
        "/dev/nvidia-modeset"
      ],
      "requireConfidentialGPU": true,
      "vendor": "nvidia"
    }
  }
}'

echo "Done. Current policy:"
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$POD_NAME" -o yaml | sed -n '/^spec:/,/^status:/p'
