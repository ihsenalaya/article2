#!/usr/bin/env bash
# Bootstraps a single-node k3s cluster on the confidential GPU VM created from
# the official Azure/az-cgpu-onboarding VMI (see EXPERIMENTS_LOG.md Phase
# 9-bis for why: the AKS-managed node pool path failed on 5 real driver
# attempts -- wrong kernel/driver-signature combination for that node image;
# the VMI comes with a pre-validated, pre-signed driver already installed).
#
# Idempotent: safe to re-run. Orchestrated from the local machine over SSH
# (not baked into cloud-init) so every step is observable and debuggable
# while a $8.82/hour VM is running -- see the ACR push saga and 5 driver
# attempts earlier in Phase 9 for why "opaque and hope it works" was
# rejected as a strategy on billed resources.
#
# Usage: ./bootstrap-cgpu-vm.sh <vm-public-ip> <ssh-user> [ssh-key-path]
set -euo pipefail

VM_IP="${1:?VM public IP required}"
SSH_USER="${2:?SSH username required}"
SSH_KEY="${3:-$HOME/.ssh/id_rsa}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KUBE_CONTEXT_NAME="cgpu-vm"
ACR_NAME="acrarticle2ebpftm2ogg"
ACR_LOGIN_SERVER="${ACR_NAME}.azurecr.io"

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$SSH_KEY")
remote() { ssh "${ssh_opts[@]}" "${SSH_USER}@${VM_IP}" "$@"; }

echo "=== 1/7: waiting for SSH ==="
for i in $(seq 1 30); do
  if remote "true" 2>/dev/null; then break; fi
  echo "  waiting... ($i/30)"; sleep 10
done
remote "true" || { echo "SSH never became reachable" >&2; exit 1; }

echo "=== 2/7: real pre-flight verification (never assumed) ==="
remote "nvidia-smi conf-compute -f 2>&1; echo '---'; nvidia-smi 2>&1 | head -15; echo '---'; sudo gpu-attestation 2>&1 | tail -5; echo '---'; cat /sys/kernel/security/lsm 2>&1"

echo "=== 3/7: installing k3s (idempotent), with tls-san set BEFORE first start ==="
# k3s's self-signed server cert only covers SANs known at cert-generation
# time (localhost/private IP/etc, not the public IP) unless told otherwise
# up front -- setting tls-san before the very first start avoids the
# regenerate-cert-after-the-fact dance (rm dynamic-cert.json + restart)
# hit during Phase 9-bis's original VM.
remote "sudo mkdir -p /etc/rancher/k3s && if ! grep -q '${VM_IP}' /etc/rancher/k3s/config.yaml 2>/dev/null; then printf 'tls-san:\n  - %s\n' '${VM_IP}' | sudo tee -a /etc/rancher/k3s/config.yaml >/dev/null; fi"
remote "if ! command -v k3s >/dev/null 2>&1; then curl -sfL https://get.k3s.io | sh -; else echo 'k3s already installed'; fi"
remote "sudo systemctl is-active k3s"

echo "=== 4/7: retrieving kubeconfig, merging as context '$KUBE_CONTEXT_NAME' ==="
# `kubectl config view --flatten` keeps the FIRST-seen definition when the
# same cluster/context/user name appears in multiple KUBECONFIG files, and
# $HOME/.kube/config is listed first -- so re-running this against a
# recreated VM (new IP, same context name, exactly what a VM
# delete+recreate cycle produces) would silently keep pointing at the OLD
# VM's stale entry. Purge any pre-existing same-named entries first so the
# merge is idempotent regardless of what the VM's IP was last time.
kubectl config delete-context "$KUBE_CONTEXT_NAME" >/dev/null 2>&1 || true
kubectl config delete-cluster "$KUBE_CONTEXT_NAME" >/dev/null 2>&1 || true
kubectl config unset "users.$KUBE_CONTEXT_NAME" >/dev/null 2>&1 || true
remote "sudo cat /etc/rancher/k3s/k3s.yaml" > /tmp/cgpu-vm-kubeconfig.yaml
sed -i "s/127.0.0.1/${VM_IP}/; s/default/${KUBE_CONTEXT_NAME}/g" /tmp/cgpu-vm-kubeconfig.yaml
KUBECONFIG="$HOME/.kube/config:/tmp/cgpu-vm-kubeconfig.yaml" kubectl config view --flatten > /tmp/merged-kubeconfig.yaml
mv /tmp/merged-kubeconfig.yaml "$HOME/.kube/config"
kubectl config use-context "$KUBE_CONTEXT_NAME"
kubectl --context "$KUBE_CONTEXT_NAME" get nodes

echo "=== 5/7: namespaces + ACR pull secret (k3s has no Azure managed-identity ACR integration like AKS) ==="
ACR_TOKEN=$(az acr login --name "$ACR_NAME" --expose-token --output tsv --query accessToken)
kubectl --context "$KUBE_CONTEXT_NAME" create namespace runtime-guard-operator-system --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
kubectl --context "$KUBE_CONTEXT_NAME" create namespace runtime-guard-agent-system --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
kubectl --context "$KUBE_CONTEXT_NAME" create namespace workloads --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
for ns in runtime-guard-operator-system runtime-guard-agent-system workloads; do
  kubectl --context "$KUBE_CONTEXT_NAME" -n "$ns" create secret docker-registry acr-pull-secret \
    --docker-server="$ACR_LOGIN_SERVER" --docker-username="00000000-0000-0000-0000-000000000000" \
    --docker-password="$ACR_TOKEN" --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
done

echo "=== 6/7: trust-anchor + agent signing keys ==="
KUBE_CONTEXT="$KUBE_CONTEXT_NAME" "$REPO_ROOT/deploy/kind/gen-trust-anchor.sh"
KUBE_CONTEXT="$KUBE_CONTEXT_NAME" "$REPO_ROOT/deploy/kind/gen-agent-key.sh"
mv "$REPO_ROOT/deploy/kind/trust-anchor.env" "$REPO_ROOT/deploy/kind/trust-anchor-cgpu-vm.env"

echo "=== 7/7: deploying CRDs/operator/agent/workloads, then linking pull secret to their ServiceAccounts ==="
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$REPO_ROOT/deploy/kind/upstream-aiplacementdecision-crd.yaml"
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$REPO_ROOT/deploy/azure/operator-manifests.yaml"
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$REPO_ROOT/deploy/azure/cgpu-vm/agent-daemonset-cgpu-vm.yaml"
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$REPO_ROOT/experiments/workloads-cgpu-vm.yaml"

# ServiceAccounts are created by the manifests just applied above, so this
# must come AFTER, not before (an earlier draft of this script patched them
# first and the patches silently no-op'd against ServiceAccounts that didn't
# exist yet).
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system patch serviceaccount runtime-guard-operator-controller-manager \
  -p '{"imagePullSecrets": [{"name": "acr-pull-secret"}]}'
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system patch serviceaccount runtime-guard-agent \
  -p '{"imagePullSecrets": [{"name": "acr-pull-secret"}]}'
kubectl --context "$KUBE_CONTEXT_NAME" -n workloads patch serviceaccount default \
  -p '{"imagePullSecrets": [{"name": "acr-pull-secret"}]}'
# Force a rollout so already-scheduled (and likely ImagePullBackOff'd) pods
# pick up the newly linked pull secret rather than waiting for their own
# natural retry backoff.
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system rollout restart deployment/runtime-guard-operator-controller-manager 2>/dev/null || true
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system rollout restart daemonset/runtime-guard-agent 2>/dev/null || true

echo "Done. Context '$KUBE_CONTEXT_NAME' is ready. Verify with:"
echo "  kubectl --context $KUBE_CONTEXT_NAME get pods -A"
