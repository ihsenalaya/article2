#!/usr/bin/env bash
# Fully automated, reproducible cgpu-vm infrastructure campaign: create VM ->
# grant least-privilege SP role -> arm safety-timeout -> bootstrap k3s/operator/
# agent/workloads -> configure GPU container runtime -> sanity-check the
# deny-all policy on gpu-workload. Chains the individual scripts in this
# directory (each already hardened against the real bugs found on
# 2026-08-01/02: missing deviceAccess.vendor, stale kubeconfig merge on VM
# recreation, sudo+glob silently no-op'ing the CNI fix -- see
# EXPERIMENTS_LOG.md) so a full campaign is one command instead of the manual,
# multi-hour, ad hoc sequence that produced those bugs in the first place.
#
# Deliberately does NOT deploy the LLM workload or run any benchmark -- that
# varies per campaign (see deploy-llm-workload.sh) while this script's job is
# just "get a healthy, GPU-exposed k3s cluster," which is always the same.
#
# MANDATORY HUMAN CHECKPOINT preserved: create-cgpu-vm.sh (and, if
# TEARDOWN_AFTER=1, teardown-cgpu-vm.sh) still require their own typed
# confirmation before touching billed resources. This script automates
# ORCHESTRATION between already-gated steps, not the authorization gate
# itself.
#
# Usage (env vars, all but RG/VM_NAME have defaults):
#   RG=rg-article2-cgpu-vm VM_NAME=cgpu-vm-01 REGION=eastus2 \
#   SSH_KEY=~/.ssh/id_rsa SAFETY_TIMEOUT_HOURS=2 TEARDOWN_AFTER=0 \
#   ./run-campaign.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CGPU_DIR="$REPO_ROOT/deploy/azure/cgpu-vm"
STATE_DIR="$CGPU_DIR/.run"
mkdir -p "$STATE_DIR"

RG="${RG:?RG required}"
VM_NAME="${VM_NAME:?VM_NAME required}"
REGION="${REGION:-eastus2}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
SSH_PUBKEY="${SSH_PUBKEY:-${SSH_KEY}.pub}"
SAFETY_TIMEOUT_HOURS="${SAFETY_TIMEOUT_HOURS:-3}"
TEARDOWN_AFTER="${TEARDOWN_AFTER:-0}"
SP_DISPLAY_NAME_PREFIX="${SP_DISPLAY_NAME_PREFIX:-sp-article2}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

log "=== 1/6: create VM (typed confirmation required -- mandatory human checkpoint) ==="
"$CGPU_DIR/create-cgpu-vm.sh" "$RG" "$VM_NAME" "$REGION" "$SSH_PUBKEY"

VM_IP=$(az vm show -d --resource-group "$RG" --name "$VM_NAME" --query publicIps -o tsv)
echo "$VM_IP" > "$STATE_DIR/vm-ip.txt"
echo "$RG" > "$STATE_DIR/rg.txt"
log "VM IP: $VM_IP (saved to $STATE_DIR/vm-ip.txt)"

log "=== 2/6: grant automation SP least-privilege role scoped to this RG ==="
SP_APP_ID=$(az ad sp list --all --query "[?starts_with(displayName, '${SP_DISPLAY_NAME_PREFIX}')].appId | [0]" -o tsv 2>/dev/null || true)
if [ -n "${SP_APP_ID:-}" ]; then
  SP_OBJECT_ID=$(az ad sp show --id "$SP_APP_ID" --query id -o tsv)
  SUB_ID=$(az account show --query id -o tsv)
  az role assignment create --assignee "$SP_OBJECT_ID" --role "Virtual Machine Contributor" \
    --scope "/subscriptions/$SUB_ID/resourceGroups/$RG" -o none 2>/dev/null \
    && log "role granted" || log "role assignment already present or non-fatal error, continuing"
else
  log "WARNING: no automation SP found matching prefix '$SP_DISPLAY_NAME_PREFIX' -- skipping role grant (safety-timeout will still work under the current user identity)"
fi

log "=== 3/6: arm safety-timeout (${SAFETY_TIMEOUT_HOURS}h) ==="
nohup "$CGPU_DIR/safety-timeout-cgpu-vm.sh" "$RG" "$SAFETY_TIMEOUT_HOURS" > "$STATE_DIR/safety-timeout.log" 2>&1 &
echo $! > "$STATE_DIR/safety-timeout.pid"
sleep 2
cat "$STATE_DIR/safety-timeout.log"
if ! kill -0 "$(cat "$STATE_DIR/safety-timeout.pid")" 2>/dev/null; then
  log "FATAL: safety-timeout failed to arm (see log above) -- aborting rather than run unprotected." >&2
  exit 1
fi

log "=== 4/6: bootstrap k3s/operator/agent/workloads ==="
"$CGPU_DIR/bootstrap-cgpu-vm.sh" "$VM_IP" azureuser "$SSH_KEY"

log "=== 5/6: GPU container runtime (nvidia.com/gpu) ==="
scp -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$CGPU_DIR/setup-gpu-container-runtime.sh" "azureuser@${VM_IP}:/tmp/"
ssh -i "$SSH_KEY" "azureuser@${VM_IP}" 'chmod +x /tmp/setup-gpu-container-runtime.sh && /tmp/setup-gpu-container-runtime.sh'

log "=== 6/6: sanity-check the deny-all policy on gpu-workload ==="
POD_UID=$(kubectl --context cgpu-vm -n workloads get pod gpu-workload -o jsonpath='{.metadata.uid}')
(
  cd "$REPO_ROOT/operator"
  source "$REPO_ROOT/deploy/kind/trust-anchor-cgpu-vm.env"
  export TRUST_ANCHOR_PRIVATE_KEY_HEX
  go run ./cmd/mint-test-decision --ttl 6h --name gpu-workload --namespace workloads \
    --target-name gpu-workload --pod-uid "$POD_UID" --node-identity "$VM_NAME" \
    --priv-key-hex "$TRUST_ANCHOR_PRIVATE_KEY_HEX"
) | kubectl --context cgpu-vm apply -f -
kubectl --context cgpu-vm -n workloads patch aiplacementdecision gpu-workload \
  --subresource=status --type=merge -p '{"status":{"decision":"allow"}}'
"$CGPU_DIR/verify-deployment.sh" cgpu-vm

log "=== infrastructure ready ==="
log "Next: deploy-llm-workload.sh to deploy vLLM with a specific config, or teardown-cgpu-vm.sh $RG when done."

if [ "$TEARDOWN_AFTER" = "1" ]; then
  log "=== TEARDOWN_AFTER=1: tearing down now (typed confirmation required) ==="
  kill "$(cat "$STATE_DIR/safety-timeout.pid")" 2>/dev/null || true
  pkill -f "port-forward svc/llm-inference-real" 2>/dev/null || true
  "$CGPU_DIR/teardown-cgpu-vm.sh" "$RG"
fi
