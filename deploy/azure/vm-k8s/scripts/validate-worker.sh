#!/usr/bin/env bash
# Generic single-node validation, factored out of validate-cluster.sh's
# per-node loop so it can run against a node that was not part of the
# original TASK-13 Terraform apply (a later join, e.g. TASK-16's H100
# worker, or a dry-run target in test-join-on-kind.sh).
#
# Records OS/kernel/containerd/kubelet/cgroup/LSM/BPF facts -- the same
# categories the experiment protocol requires recording for the whole cluster --
# scoped to one node. No GPU-specific checks here; see validate-gpu-worker.sh.
#
# Usage: ./validate-worker.sh <node-name> <target-public-ip> <ssh-user> [ssh-key-path] [out-dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$TF_DIR/.run"

NODE_NAME="${1:?node name required}"
TARGET_IP="${2:?target node public/reachable IP required}"
SSH_USER="${3:?ssh user required}"
SSH_KEY="${4:-$HOME/.ssh/id_ed25519}"
OUT_DIR="${5:-$RUN_DIR/validation-${NODE_NAME}}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$RUN_DIR/kubeconfig}"

mkdir -p "$OUT_DIR"

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")
remote_capture() {
  local name="$1"
  shift
  ssh "${ssh_opts[@]}" "${SSH_USER}@${TARGET_IP}" "$@" > "$OUT_DIR/${name}.out" 2> "$OUT_DIR/${name}.err"
}

kubectl --kubeconfig "$KUBECONFIG_PATH" get "node/$NODE_NAME" -o wide > "$OUT_DIR/kubectl-get-node-wide.txt"
kubectl --kubeconfig "$KUBECONFIG_PATH" get "node/$NODE_NAME" -o jsonpath='{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\t"}{.status.nodeInfo.kernelVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}' > "$OUT_DIR/node-info.tsv"

remote_capture "kernel" "uname -a"
remote_capture "os-release" "cat /etc/os-release"
remote_capture "containerd-version" "containerd --version"
remote_capture "kubelet-version" "kubelet --version"
remote_capture "cgroups" "findmnt -T /sys/fs/cgroup && cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true"
remote_capture "lsm" "cat /sys/kernel/security/lsm 2>/dev/null || true"
remote_capture "bpftool-path" "command -v bpftool && bpftool version"
remote_capture "bpf-feature-probe" "sudo bpftool feature probe kernel unprivileged"

cat > "$OUT_DIR/summary.txt" <<SUMMARY
Single-node validation for '$NODE_NAME' ($TARGET_IP)

- node status: $OUT_DIR/kubectl-get-node-wide.txt
- versions: $OUT_DIR/node-info.tsv
- kernel/containerd/cgroups/LSM/BPF: $OUT_DIR/*.{out,err}

No GPU/confidential-computing checks performed here -- see validate-gpu-worker.sh.
SUMMARY

cat "$OUT_DIR/summary.txt"
