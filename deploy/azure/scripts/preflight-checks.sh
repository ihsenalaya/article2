#!/usr/bin/env bash
# Phase 9 pre-flight checks, run against the real AKS cluster before
# redeploying anything: confirms the two properties the whole mission
# depends on are actually true on this hardware, rather than assumed.
#
# 1. BPF-LSM available on the GPU node (our agent's enforce mode needs it;
#    audit mode works either way, but claiming "enforce" results without
#    this check would be exactly the kind of unverified claim rule 1
#    forbids).
# 2. The H100 is actually running in confidential-computing mode (SNP), not
#    silently falling back to a normal (non-confidential) GPU.
#
# Usage: KUBE_CONTEXT=<aks-context> ./preflight-checks.sh
set -euo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:?set KUBE_CONTEXT to the AKS context (az aks get-credentials --admin ... first)}"

echo "=== BPF-LSM check (GPU node) ==="
GPU_NODE=$(kubectl --context "$KUBE_CONTEXT" get nodes -l "kubernetes.azure.com/agentpool=gpuh100" -o jsonpath='{.items[0].metadata.name}')
echo "GPU node: $GPU_NODE"

kubectl --context "$KUBE_CONTEXT" debug node/"$GPU_NODE" -it --image=busybox -- \
  cat /host/sys/kernel/security/lsm > /tmp/lsm-check.txt 2>&1 || true
LSM_LINE=$(grep -v "^Creating\|^If you\|^Waiting\|^Pod" /tmp/lsm-check.txt || true)
echo "Active LSMs: $LSM_LINE"
if echo "$LSM_LINE" | grep -q "bpf"; then
  echo "RESULT: BPF-LSM is ACTIVE on $GPU_NODE -- enforce mode is a valid claim here."
else
  echo "RESULT: BPF-LSM NOT found in active LSM list on $GPU_NODE."
  echo "Any 'enforce mode' claim for this run must be scoped to audit-only, or"
  echo "the AKS node OS config must be changed (e.g. via a custom node image /"
  echo "kernel boot params) before enforce-mode results can be reported -- do"
  echo "not report enforce-mode numbers without re-running this check green."
fi

echo ""
echo "=== Confidential GPU (SNP) check ==="
kubectl --context "$KUBE_CONTEXT" debug node/"$GPU_NODE" -it --image=mcr.microsoft.com/azurelinux/base/core:3.0 -- \
  chroot /host sh -c 'nvidia-smi conf-compute -f 2>&1 || echo "nvidia-smi conf-compute not available"' \
  > /tmp/cc-check.txt 2>&1 || true
cat /tmp/cc-check.txt
echo ""
echo "RESULT: inspect the output above for 'CC status: ON' (or equivalent)."
echo "Do not report 'confidential GPU' results if this does not confirm ON --"
echo "report exactly what this command returned, including if it errored."
