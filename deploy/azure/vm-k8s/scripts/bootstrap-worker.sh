#!/usr/bin/env bash
# Generic single-node OS preparation for joining an EXISTING kubeadm cluster
# as an additional worker (TASK-14/15/16 "future H100 join design",
# the experiment protocol: the H100 worker must join the existing TASK-13 cluster
# without rebuilding it).
#
# Deliberately does not read Terraform outputs for the TARGET node: this
# script must work identically whether the target is a brand-new Azure VM
# not yet in any Terraform state, or a throwaway container used to dry-run
# the join flow against a local kind control plane (see
# scripts/test-join-on-kind.sh). Only join-worker.sh needs the control-plane
# Terraform outputs, because the control plane IS already Terraform-managed
# (TASK-13).
#
# Idempotent: safe to re-run. Installs the exact same containerd/kubeadm
# stack as bootstrap-cluster.sh's install_kubernetes_node, factored out here
# so both the 2-node TASK-13 bring-up and any later single-node join
# (TASK-14 fix retry, TASK-16 H100 join) share one implementation instead of
# drifting apart.
#
# Usage: ./bootstrap-worker.sh <public-ip> <ssh-user> [ssh-key-path]
set -euo pipefail

TARGET_IP="${1:?target node public/reachable IP required}"
SSH_USER="${2:?ssh user required}"
SSH_KEY="${3:-$HOME/.ssh/id_ed25519}"
KUBERNETES_MINOR="${KUBERNETES_MINOR:-v1.30}"
SSH_PORT="${SSH_PORT:-22}"

ssh_opts=(-p "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")
remote() { ssh "${ssh_opts[@]}" "${SSH_USER}@${TARGET_IP}" "$@"; }

echo "=== waiting for SSH on $TARGET_IP ==="
for attempt in $(seq 1 60); do
  if remote "true" >/dev/null 2>&1; then break; fi
  echo "  waiting for SSH ($attempt/60)"
  sleep 10
done
remote "true" || { echo "SSH never became reachable on $TARGET_IP" >&2; exit 1; }

echo "=== installing containerd + kubeadm/kubelet/kubectl on $TARGET_IP ==="
remote "KUBERNETES_MINOR='$KUBERNETES_MINOR' bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

sudo swapoff -a || true
sudo sed -i.bak '/ swap / s/^/#/' /etc/fstab || true

cat <<'EOF' | sudo tee /etc/modules-load.d/k8s.conf >/dev/null
overlay
br_netfilter
EOF
sudo modprobe overlay || true
sudo modprobe br_netfilter || true
# On a real VM kernel these are loadable modules and modprobe above must
# succeed. On some container-hosting kernels (e.g. this repo's own kind
# dry-run target, WSL2's kernel) the same features are compiled directly
# into the kernel, so there is no separate .ko file and modprobe correctly
# reports "not found" -- that is not a real failure. Verify the actual
# capability instead of trusting either modprobe's exit code or an
# assumption: report what is really there.
grep -qw overlay /proc/filesystems || echo "WARNING: overlay filesystem support not detected (neither module nor built-in)" >&2
[ -e /proc/sys/net/bridge/bridge-nf-call-iptables ] || echo "WARNING: br_netfilter sysctls not present (neither module nor built-in) -- bridge packet filtering for the CNI will not work on this node" >&2

cat <<'EOF' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
sudo sysctl --system >/dev/null || echo "WARNING: sysctl --system reported an error -- check whether bridge-nf sysctls above actually applied" >&2

sudo apt-get update
sudo apt-get install -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" apt-transport-https ca-certificates curl gpg containerd
# linux-tools-common/linux-tools-azure provide bpftool on a genuine Ubuntu
# Azure kernel; they do not exist on every base image this script might run
# against (e.g. this repo's own kind dry-run target runs Debian, not
# Ubuntu). Best-effort only -- the bpftool symlink step right below already
# tolerates bpftool being unavailable, so a failure here must not be fatal.
sudo apt-get install -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" linux-tools-common linux-tools-azure || echo "linux-tools-common/linux-tools-azure not installable on this image -- bpftool may be unavailable, continuing"

if ! command -v bpftool >/dev/null 2>&1; then
  bpftool_path="$(find /usr/lib/linux-tools* -type f -name bpftool 2>/dev/null | sort -V | tail -1 || true)"
  if [ -n "$bpftool_path" ]; then
    sudo ln -sf "$bpftool_path" /usr/local/sbin/bpftool
  fi
fi

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml >/dev/null
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
sudo systemctl enable --now containerd
sudo systemctl restart containerd

if ! dpkg -s kubelet kubeadm kubectl >/dev/null 2>&1; then
  sudo mkdir -p /etc/apt/keyrings
  curl -fsSL "https://pkgs.k8s.io/core:/stable:/${KUBERNETES_MINOR}/deb/Release.key" |
    sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
  echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/${KUBERNETES_MINOR}/deb/ /" |
    sudo tee /etc/apt/sources.list.d/kubernetes.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y -o Dpkg::Options::="--force-confold" -o Dpkg::Options::="--force-confdef" kubelet kubeadm kubectl
  sudo apt-mark hold kubelet kubeadm kubectl
fi

sudo systemctl enable kubelet
REMOTE

echo "=== node prep complete on $TARGET_IP, ready for join-worker.sh ==="
