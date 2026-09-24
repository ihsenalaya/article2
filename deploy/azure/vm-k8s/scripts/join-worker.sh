#!/usr/bin/env bash
# Joins an already-prepared node (bootstrap-worker.sh already run on it) to
# the EXISTING TASK-13 control plane as an additional worker, then applies
# the requested labels. This is the reusable core of the experiment protocol's
# "future H100 join design": the control plane is never reinitialized, only
# a fresh join token is minted and consumed.
#
# Reads the control-plane connection info from the TASK-13 Terraform state
# (same convention as bootstrap-cluster.sh / validate-cluster.sh) because
# the control plane already exists there. The target node's own IP is a
# plain argument, not a Terraform output, so this also works against a
# throwaway dry-run target (see test-join-on-kind.sh) that was never part of
# any Terraform state.
#
# Usage: ./join-worker.sh <target-public-ip> <target-node-name> <ssh-user> [ssh-key-path] [comma,separated,labels]
# Example: ./join-worker.sh 20.1.2.3 vm-a2-vmk8s-20260808-h100 azureuser ~/.ssh/id_ed25519 accelerator=nvidia-h100,confidential-compute=true
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$TF_DIR/.run"

TARGET_IP="${1:?target node public/reachable IP required}"
TARGET_NODE_NAME="${2:?target node name required (must match hostname -s on the target)}"
SSH_USER="${3:?ssh user required}"
SSH_KEY="${4:-$HOME/.ssh/id_ed25519}"
LABELS="${5:-}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$RUN_DIR/kubeconfig}"
TARGET_SSH_PORT="${SSH_PORT:-22}"

tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1"
}

CONTROL_PLANE_PUBLIC_IP="$(tf_output control_plane_public_ip)"
ADMIN_USER="$(tf_output admin_username)"

cp_ssh_opts=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")
target_ssh_opts=(-p "$TARGET_SSH_PORT" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")
remote_cp() { ssh "${cp_ssh_opts[@]}" "${ADMIN_USER}@${CONTROL_PLANE_PUBLIC_IP}" "$@"; }
remote_target() { ssh "${target_ssh_opts[@]}" "${SSH_USER}@${TARGET_IP}" "$@"; }

echo "=== minting a fresh join token from the control plane ($CONTROL_PLANE_PUBLIC_IP) ==="
join_command="$(remote_cp "sudo kubeadm token create --print-join-command --ttl 2h")"
echo "join command retrieved (token not printed to stdout of this script)"

echo "=== joining $TARGET_IP as node '$TARGET_NODE_NAME' ==="
remote_target "JOIN_COMMAND='$join_command' NODE_NAME='$TARGET_NODE_NAME' bash -s" <<'REMOTE'
set -euo pipefail
if [ -f /etc/kubernetes/kubelet.conf ]; then
  echo "kubelet.conf already present -- node already joined, skipping (idempotent)"
else
  sudo $JOIN_COMMAND --cri-socket unix:///run/containerd/containerd.sock --node-name "$NODE_NAME"
fi
REMOTE

echo "=== waiting for node '$TARGET_NODE_NAME' to register and go Ready ==="
for attempt in $(seq 1 60); do
  if kubectl --kubeconfig "$KUBECONFIG_PATH" get node "$TARGET_NODE_NAME" >/dev/null 2>&1 &&
     kubectl --kubeconfig "$KUBECONFIG_PATH" wait --for=condition=Ready "node/$TARGET_NODE_NAME" --timeout=20s >/dev/null 2>&1; then
    break
  fi
  echo "  waiting for node '$TARGET_NODE_NAME' Ready ($attempt/60)"
  sleep 10
done
kubectl --kubeconfig "$KUBECONFIG_PATH" get "node/$TARGET_NODE_NAME" -o wide

if [ -n "$LABELS" ]; then
  echo "=== applying labels: $LABELS ==="
  IFS=',' read -ra label_array <<< "$LABELS"
  kubectl --kubeconfig "$KUBECONFIG_PATH" label node "$TARGET_NODE_NAME" "${label_array[@]}" --overwrite
  echo "NOTE: labels do not prove the underlying properties (confidential-compute, GPU presence)."
  echo "Only independent attestation (validate-gpu-worker.sh) does -- the experiment protocol."
fi

kubectl --kubeconfig "$KUBECONFIG_PATH" get "node/$TARGET_NODE_NAME" --show-labels
