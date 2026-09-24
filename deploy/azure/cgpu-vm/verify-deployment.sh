#!/usr/bin/env bash
# Post-deployment verification for the cgpu-vm context. Written and tested
# against kind first (free) after a false alarm on the real VM: evidence
# objects live in the `aiops-system` namespace by default (agent flag
# --evidence-namespace, env EVIDENCE_NAMESPACE), NOT in the workload's own
# namespace -- checking the wrong namespace looked exactly like "no evidence
# is ever produced" and nearly triggered unnecessary debugging on a billed
# VM. See EXPERIMENTS_LOG.md Phase 9-bis for the full account.
#
# Usage: ./verify-deployment.sh [kube-context]
set -uo pipefail

CTX="${1:-cgpu-vm}"

echo "=== nodes ==="
kubectl --context "$CTX" get nodes -o wide

echo ""
echo "=== pods (all namespaces) ==="
kubectl --context "$CTX" get pods -A -o wide

echo ""
echo "=== RuntimeSecurityPolicy (in the workload's own namespace) ==="
kubectl --context "$CTX" -n workloads get runtimesecuritypolicy

echo ""
echo "=== RuntimePlacementEvidence (in aiops-system, NOT workloads) ==="
kubectl --context "$CTX" -n aiops-system get runtimeplacementevidence

echo ""
echo "=== gpu-workload evidence detail (behavior counters, signature freshness) ==="
kubectl --context "$CTX" -n aiops-system get runtimeplacementevidence gpu-workload -o yaml 2>/dev/null | grep -A 20 "^status:" || \
  echo "NOT FOUND -- if pods above are Running and policy is active, wait one more evidence-loop interval (~10s) and retry before assuming a real problem."

echo ""
echo "=== real device check on the GPU node itself ==="
echo "(expect this to be a REAL functioning nvidia-smi/device, unlike kind/AKS)"
