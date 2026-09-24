#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$TF_DIR/.run"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
KUBECONFIG_PATH="${KUBECONFIG_PATH:-$RUN_DIR/kubeconfig}"
OUT_DIR="${OUT_DIR:-$RUN_DIR/validation}"

mkdir -p "$OUT_DIR"

tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1"
}

ADMIN_USER="$(tf_output admin_username)"
CONTROL_PLANE_PUBLIC_IP="$(tf_output control_plane_public_ip)"
WORKER_PUBLIC_IP="$(tf_output worker_public_ip)"

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")

remote_capture() {
  local host="$1"
  local name="$2"
  shift 2
  ssh "${ssh_opts[@]}" "${ADMIN_USER}@${host}" "$@" > "$OUT_DIR/${name}.out" 2> "$OUT_DIR/${name}.err"
}

kubectl --kubeconfig "$KUBECONFIG_PATH" get nodes -o wide > "$OUT_DIR/kubectl-get-nodes-wide.txt"
kubectl --kubeconfig "$KUBECONFIG_PATH" get pods -A -o wide > "$OUT_DIR/kubectl-get-pods-all-wide.txt"
kubectl --kubeconfig "$KUBECONFIG_PATH" -n kube-system get daemonsets,deployments -o wide > "$OUT_DIR/kube-system-workloads.txt"
kubectl --kubeconfig "$KUBECONFIG_PATH" get nodes -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.nodeInfo.kubeletVersion}{"\t"}{.status.nodeInfo.containerRuntimeVersion}{"\t"}{.status.nodeInfo.kernelVersion}{"\t"}{.status.nodeInfo.osImage}{"\n"}{end}' > "$OUT_DIR/node-info.tsv"

for entry in "control-plane:$CONTROL_PLANE_PUBLIC_IP" "worker:$WORKER_PUBLIC_IP"; do
  role="${entry%%:*}"
  host="${entry#*:}"
  remote_capture "$host" "${role}-kernel" "uname -a"
  remote_capture "$host" "${role}-os-release" "cat /etc/os-release"
  remote_capture "$host" "${role}-containerd-version" "containerd --version"
  remote_capture "$host" "${role}-kubelet-version" "kubelet --version"
  remote_capture "$host" "${role}-cgroups" "findmnt -T /sys/fs/cgroup && cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || true"
  remote_capture "$host" "${role}-lsm" "cat /sys/kernel/security/lsm 2>/dev/null || true"
  remote_capture "$host" "${role}-bpftool-path" "command -v bpftool && bpftool version"
  remote_capture "$host" "${role}-bpf-feature-probe" "sudo bpftool feature probe kernel unprivileged"
done

cat > "$OUT_DIR/summary.txt" <<SUMMARY
TASK-13 Azure VM Kubernetes validation artifacts

- nodes: $OUT_DIR/kubectl-get-nodes-wide.txt
- pods: $OUT_DIR/kubectl-get-pods-all-wide.txt
- CNI/workloads: $OUT_DIR/kube-system-workloads.txt
- versions: $OUT_DIR/node-info.tsv
- kernel/containerd/cgroups/LSM/BPF: ${OUT_DIR}/*.{out,err}
SUMMARY

cat "$OUT_DIR/summary.txt"
