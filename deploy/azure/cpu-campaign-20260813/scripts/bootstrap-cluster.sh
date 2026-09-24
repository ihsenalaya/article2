#!/usr/bin/env bash
# Bring up a 2-node kubeadm cluster (control-plane + worker) on the VMs this
# directory's Terraform config provisions. Adapted from the prior CPU
# campaign's proven deploy/azure/vm-k8s/scripts/bootstrap-cluster.sh —
# same containerd/kubeadm/Calico versions (experiment protocol rule 13: prefer a
# configuration close to the previous CPU campaign), pointed at this
# campaign's own dedicated Terraform state/resource group.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$TF_DIR/.run"

SSH_KEY="${SSH_KEY:-$HOME/.ssh/article2_cpucampaign_ed25519}"
KUBERNETES_MINOR="${KUBERNETES_MINOR:-v1.30}"
POD_CIDR="${POD_CIDR:-192.168.0.0/16}"
CALICO_VERSION="${CALICO_VERSION:-v3.28.2}"
KUBE_CONTEXT_NAME="${KUBE_CONTEXT_NAME:-article2-cpu-campaign-20260813}"

mkdir -p "$RUN_DIR"

tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1"
}

ADMIN_USER="$(tf_output admin_username)"
CONTROL_PLANE_PUBLIC_IP="$(tf_output control_plane_public_ip)"
CONTROL_PLANE_PRIVATE_IP="$(tf_output control_plane_private_ip)"
WORKER_PUBLIC_IP="$(tf_output worker_public_ip)"

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")

remote() {
  local host="$1"
  shift
  ssh "${ssh_opts[@]}" "${ADMIN_USER}@${host}" "$@"
}

wait_for_ssh() {
  local host="$1"
  for attempt in $(seq 1 60); do
    if remote "$host" "true" >/dev/null 2>&1; then
      return 0
    fi
    echo "waiting for SSH on $host ($attempt/60)"
    sleep 10
  done
  echo "SSH did not become available on $host" >&2
  return 1
}

install_kubernetes_node() {
  local host="$1"
  remote "$host" "KUBERNETES_MINOR='$KUBERNETES_MINOR' bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

sudo swapoff -a || true
sudo sed -i.bak '/ swap / s/^/#/' /etc/fstab || true

cat <<'EOF' | sudo tee /etc/modules-load.d/k8s.conf >/dev/null
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter

cat <<'EOF' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf >/dev/null
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
sudo sysctl --system >/dev/null

sudo apt-get update
sudo apt-get install -y apt-transport-https ca-certificates curl gpg containerd linux-tools-common linux-tools-azure

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
  sudo apt-get install -y kubelet kubeadm kubectl
  sudo apt-mark hold kubelet kubeadm kubectl
fi

sudo systemctl enable kubelet
REMOTE
}

bootstrap_control_plane() {
  remote "$CONTROL_PLANE_PUBLIC_IP" \
    "CONTROL_PLANE_PRIVATE_IP='$CONTROL_PLANE_PRIVATE_IP' CONTROL_PLANE_PUBLIC_IP='$CONTROL_PLANE_PUBLIC_IP' POD_CIDR='$POD_CIDR' CALICO_VERSION='$CALICO_VERSION' bash -s" <<'REMOTE'
set -euo pipefail

if [ ! -f /etc/kubernetes/admin.conf ]; then
  sudo kubeadm init \
    --apiserver-advertise-address "$CONTROL_PLANE_PRIVATE_IP" \
    --apiserver-cert-extra-sans "$CONTROL_PLANE_PUBLIC_IP,$CONTROL_PLANE_PRIVATE_IP" \
    --pod-network-cidr "$POD_CIDR" \
    --cri-socket unix:///run/containerd/containerd.sock \
    --node-name "$(hostname -s)"
fi

mkdir -p "$HOME/.kube"
sudo cp /etc/kubernetes/admin.conf "$HOME/.kube/config"
sudo chown "$(id -u):$(id -g)" "$HOME/.kube/config"

kubectl --kubeconfig "$HOME/.kube/config" apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
REMOTE
}

join_worker() {
  local join_command
  join_command="$(remote "$CONTROL_PLANE_PUBLIC_IP" "sudo kubeadm token create --print-join-command --ttl 2h")"

  remote "$WORKER_PUBLIC_IP" "JOIN_COMMAND='$join_command' bash -s" <<'REMOTE'
set -euo pipefail
if [ ! -f /etc/kubernetes/kubelet.conf ]; then
  sudo $JOIN_COMMAND --cri-socket unix:///run/containerd/containerd.sock --node-name "$(hostname -s)"
fi
REMOTE
}

write_local_kubeconfig() {
  remote "$CONTROL_PLANE_PUBLIC_IP" "sudo cat /etc/kubernetes/admin.conf" > "$RUN_DIR/kubeconfig.raw"
  sed "s#server: https://.*:6443#server: https://${CONTROL_PLANE_PUBLIC_IP}:6443#" "$RUN_DIR/kubeconfig.raw" > "$RUN_DIR/kubeconfig"
  chmod 600 "$RUN_DIR/kubeconfig"
  kubectl --kubeconfig "$RUN_DIR/kubeconfig" config rename-context kubernetes-admin@kubernetes "$KUBE_CONTEXT_NAME" >/dev/null 2>&1 || true
  kubectl --kubeconfig "$RUN_DIR/kubeconfig" config use-context "$KUBE_CONTEXT_NAME" >/dev/null
}

wait_for_cluster() {
  for attempt in $(seq 1 60); do
    if kubectl --kubeconfig "$RUN_DIR/kubeconfig" wait --for=condition=Ready nodes --all --timeout=20s >/dev/null 2>&1; then
      kubectl --kubeconfig "$RUN_DIR/kubeconfig" get nodes -o wide
      return 0
    fi
    echo "waiting for Kubernetes nodes to become Ready ($attempt/60)"
    kubectl --kubeconfig "$RUN_DIR/kubeconfig" get nodes -o wide || true
    sleep 10
  done
  return 1
}

install_metrics_server() {
  # Not part of the original Task 01/02 bootstrap -- added when Task 08's
  # scale-generator needed PodMetrics (CPU/memory sampling). kubeadm
  # clusters need --kubelet-insecure-tls since kubelet's serving cert isn't
  # signed for a name metrics-server's default config trusts.
  kubectl --kubeconfig "$RUN_DIR/kubeconfig" apply -f \
    https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml
  kubectl --kubeconfig "$RUN_DIR/kubeconfig" patch deployment metrics-server -n kube-system --type=json \
    -p '[{"op":"add","path":"/spec/template/spec/containers/0/args/-","value":"--kubelet-insecure-tls"}]'
  kubectl --kubeconfig "$RUN_DIR/kubeconfig" -n kube-system rollout status deployment/metrics-server --timeout=120s
}

wait_for_ssh "$CONTROL_PLANE_PUBLIC_IP"
wait_for_ssh "$WORKER_PUBLIC_IP"
install_kubernetes_node "$CONTROL_PLANE_PUBLIC_IP"
install_kubernetes_node "$WORKER_PUBLIC_IP"
bootstrap_control_plane
join_worker
write_local_kubeconfig
wait_for_cluster
install_metrics_server

echo "Kubeconfig: $RUN_DIR/kubeconfig"
echo
echo "NOTE: this cluster's VMs have a daily auto-shutdown schedule enabled"
echo "by Terraform (cost-protection backstop, experiment protocol rule 14)."
echo "For a multi-hour/multi-day live campaign, disable it after"
echo "provisioning (re-enable, or just let teardown remove it, when done):"
echo "  az resource update -g <resource-group> \\"
echo "    -n shutdown-computevm-<control-plane-vm-name> \\"
echo "    --resource-type Microsoft.DevTestLab/schedules --set properties.status=Disabled"
echo "  (repeat for the worker VM's schedule)"
echo
echo "NOTE: real BPF-LSM enforcement on the worker node is NOT enabled by"
echo "this script (Task 10) -- it requires a GRUB boot-parameter change and"
echo "a reboot, a deliberately separate, opt-in step. Run:"
echo "  bash \"$SCRIPT_DIR/enable-bpf-lsm.sh\""
