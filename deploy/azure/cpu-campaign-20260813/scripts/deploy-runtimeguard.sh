#!/usr/bin/env bash
# Task 02: deploy RuntimeGuard (Operator + eBPF agent DaemonSet) onto this
# campaign's cluster. Idempotent. Requires:
#  - $RUN_DIR/kubeconfig (from bootstrap-cluster.sh)
#  - $RUN_DIR/secrets/trust-anchor.env and agent-signing.env (PUBLIC_KEY_HEX /
#    PRIVATE_KEY_HEX, generated via `go run ./cmd/gen-keypair` in operator/,
#    gitignored -- never committed)
#  - an active `az login` session with pull access to the ACR the images were
#    pushed to (az acr build already ran separately for this task)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$TF_DIR/../../.." && pwd)"
RUN_DIR="$TF_DIR/.run"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$RUN_DIR/kubeconfig}"
ACR_NAME="${ACR_NAME:-acrarticle2ebpftm2ogg}"

export KUBECONFIG="$KUBECONFIG_PATH"

echo "=== applying CRDs ==="
kubectl apply -f "$REPO_ROOT/operator/config/crd/bases/aiops.imperium.io_runtimesecuritypolicies.yaml"
kubectl apply -f "$REPO_ROOT/operator/config/crd/bases/aiops.imperium.io_runtimeplacementevidences.yaml"
kubectl apply -f "$REPO_ROOT/deploy/kind/upstream-aiplacementdecision-crd.yaml"

echo "=== namespaces ==="
kubectl apply -f "$TF_DIR/manifests/namespaces.yaml"

echo "=== ACR pull secret (long-lived admin credentials, not a short-lived AAD token) ==="
# Task 08 found the hard way that az acr login --expose-token's AAD refresh
# token is short-lived (~3h15m): it expired mid-campaign during a VM outage,
# causing every subsequent image pull to fail with ImagePullBackOff (see
# artifacts/experiments/scale/exclusions.md). Using the registry's static
# admin credentials instead means this secret never needs refreshing for the
# life of the campaign. The trailing `tr -d '\r\n'` matters: az's tsv output
# on this environment carries a trailing \r that, left in, silently corrupts
# the secret's basic-auth credential (401 Unauthorized) without ANY error at
# secret-creation time -- also found the hard way, same exclusions.md.
az acr update -n "$ACR_NAME" --admin-enabled true -o none
ACR_USER="$(az acr credential show -n "$ACR_NAME" --query username -o tsv | tr -d '\r\n')"
ACR_PASS="$(az acr credential show -n "$ACR_NAME" --query "passwords[0].value" -o tsv | tr -d '\r\n')"
for ns in runtime-guard-operator-system runtime-guard-agent-system workloads; do
  kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n "$ns" delete secret acr-pull-secret --ignore-not-found
  kubectl -n "$ns" create secret docker-registry acr-pull-secret \
    --docker-server="${ACR_NAME}.azurecr.io" \
    --docker-username="$ACR_USER" \
    --docker-password="$ACR_PASS"
done

echo "=== trust anchor + agent signing key secrets ==="
# shellcheck disable=SC1090
source "$RUN_DIR/secrets/trust-anchor.env"
kubectl -n aiops-system create configmap attestation-scheduler-public-key \
  --from-literal=publicKeyHex="$PUBLIC_KEY_HEX" \
  --dry-run=client -o yaml | kubectl apply -f -

# shellcheck disable=SC1090
source "$RUN_DIR/secrets/agent-signing.env"
kubectl -n aiops-system create secret generic runtime-guard-agent-signing-key \
  --from-literal=privateKeyHex="$PRIVATE_KEY_HEX" \
  --dry-run=client -o yaml | kubectl apply -f -
# The DaemonSet's namespace also needs it: the agent reads AGENT_SIGNING_KEY_HEX
# from a secretKeyRef in its own namespace (runtime-guard-agent-system).
kubectl -n runtime-guard-agent-system create secret generic runtime-guard-agent-signing-key \
  --from-literal=privateKeyHex="$PRIVATE_KEY_HEX" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "=== operator RBAC + Deployment ==="
kubectl apply -f "$TF_DIR/manifests/operator-rbac-deployment.yaml"

echo "=== agent RBAC + DaemonSet ==="
kubectl apply -f "$TF_DIR/manifests/agent-daemonset.yaml"

echo "=== waiting for rollout ==="
kubectl -n runtime-guard-operator-system rollout status deployment/runtime-guard-operator-controller-manager --timeout=180s
kubectl -n runtime-guard-agent-system rollout status daemonset/runtime-guard-agent --timeout=180s

echo "=== status ==="
kubectl -n runtime-guard-operator-system get pods -o wide
kubectl -n runtime-guard-agent-system get pods -o wide
