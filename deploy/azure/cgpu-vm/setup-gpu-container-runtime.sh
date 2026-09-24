#!/usr/bin/env bash
# Configures k3s's containerd to expose the GPU to pods via the standard
# `nvidia.com/gpu` resource + RuntimeClass mechanism (same model AKS's own
# docs use), rather than the manual hostPath device-mount trick used for
# Phase 9-bis's simple device-access policy test. Needed for llm-inference
# to actually run CUDA compute (vLLM), not just observe a device path.
#
# UNVERIFIED DRAFT as of writing -- the VMI is documented to ship Docker +
# CUDA + driver pre-installed, but whether nvidia-container-toolkit is
# already wired for k3s's own (non-Docker) containerd instance specifically
# has not been confirmed empirically yet. This script checks and configures
# rather than assuming. Run it, read its real output, fix before trusting
# results.
#
# Usage: ssh into the VM and run this directly, or:
#   ssh -i ~/.ssh/id_rsa azureuser@<ip> 'bash -s' < setup-gpu-container-runtime.sh
set -euo pipefail

echo "=== checking whether nvidia.com/gpu is already exposed on the node ==="
# Phase 9-ter (2026-08-01) ran this script's reconfigure+restart unconditionally
# on an already-working node and it triggered a real CNI regression (see
# EXPERIMENTS_LOG.md) -- containerd's CRI plugin was pointed at system-default
# CNI paths (/etc/cni/net.d, /opt/cni/bin) while k3s actually writes its
# flannel conflist/binaries under /var/lib/rancher/k3s/*, a latent mismatch
# on this VMI that a k3s restart exposes regardless of what triggered it.
# nvidia.com/gpu was ALREADY present in node capacity from a prior run, so the
# reconfigure was pure redundant risk. Never restart k3s here without need.
if sudo k3s kubectl get nodes -o jsonpath='{.items[0].status.capacity.nvidia\.com/gpu}' 2>/dev/null | grep -q .; then
  echo "nvidia.com/gpu already present in node capacity -- nothing to do, not touching containerd/k3s."
  sudo k3s kubectl get nodes -o jsonpath='{.items[0].status.capacity}'
  echo ""
  exit 0
fi

echo "=== checking for nvidia-container-toolkit ==="
if ! command -v nvidia-ctk >/dev/null 2>&1; then
  echo "nvidia-ctk not found -- installing nvidia-container-toolkit"
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
  curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
    sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
    sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
  sudo apt-get update -qq
  sudo apt-get install -y -qq nvidia-container-toolkit
else
  echo "nvidia-ctk already present: $(nvidia-ctk --version)"
fi

echo "=== pre-empting the known CNI path mismatch BEFORE restarting k3s ==="
# k3s's own flannel conflist/CNI binaries live under /var/lib/rancher/k3s/*,
# not the system-default paths containerd's CRI plugin looks at by default.
# Applying this fix proactively (idempotent: safe even if already correct)
# means the restart below cannot reproduce the 2026-08-01 regression.
sudo mkdir -p /etc/cni/net.d
# The shell expands *.conflist BEFORE sudo runs, and this user can't read
# the k3s-owned source dir -- so a bare `sudo cp *.conflist ...` silently
# copies nothing (glob fails to expand, cp gets no args, `|| true` hides
# it). Wrapping the whole glob+copy inside `sudo bash -c` fixes this: the
# expansion then happens with root's read access. This exact bug bit the
# 2026-08-02 VM recreation for real -- caught and fixed the same day.
sudo bash -c 'cp --update=none /var/lib/rancher/k3s/agent/etc/cni/net.d/*.conflist /etc/cni/net.d/ 2>/dev/null' || true
sudo mkdir -p /opt/cni
sudo ln -sfn /var/lib/rancher/k3s/data/current/bin /opt/cni/bin

echo "=== configuring k3s containerd for the nvidia runtime ==="
# k3s uses a templated containerd config specifically so tools like this
# don't have to hand-edit the generated one directly.
sudo nvidia-ctk runtime configure --runtime=containerd --config=/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl
sudo systemctl restart k3s

echo "=== waiting for node Ready (real check, not a blind sleep) ==="
for i in $(seq 1 24); do
  if sudo k3s kubectl get nodes 2>/dev/null | grep -q ' Ready'; then
    echo "node Ready after ${i}x5s"
    break
  fi
  echo "  waiting for node Ready... ($i/24)"; sleep 5
done
sudo k3s kubectl get nodes -o wide
sudo systemctl is-active k3s

echo "=== applying RuntimeClass + NVIDIA device plugin ==="
cat <<'EOF' | sudo k3s kubectl apply -f -
apiVersion: node.k8s.io/v1
kind: RuntimeClass
metadata:
  name: nvidia
handler: nvidia
EOF

cat <<'EOF' | sudo k3s kubectl apply -f -
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: nvidia-device-plugin-daemonset
  namespace: kube-system
spec:
  selector:
    matchLabels:
      name: nvidia-device-plugin-ds
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        name: nvidia-device-plugin-ds
    spec:
      priorityClassName: system-node-critical
      runtimeClassName: nvidia
      containers:
      - image: nvcr.io/nvidia/k8s-device-plugin:v0.18.0
        name: nvidia-device-plugin-ctr
        env:
          - name: FAIL_ON_INIT_ERROR
            value: "false"
        securityContext:
          allowPrivilegeEscalation: false
          capabilities:
            drop: ["ALL"]
        volumeMounts:
        - name: device-plugin
          mountPath: /var/lib/kubelet/device-plugins
      volumes:
      - name: device-plugin
        hostPath:
          path: /var/lib/kubelet/device-plugins
EOF

echo "=== verification (real output, don't assume) ==="
sleep 15
sudo k3s kubectl -n kube-system get pods -l name=nvidia-device-plugin-ds
sudo k3s kubectl get nodes -o jsonpath='{.items[0].status.capacity}'
echo ""
echo "Expect 'nvidia.com/gpu: \"1\"' in the capacity output above. If absent, this approach"
echo "did not work on this VMI -- fall back to manual hostPath device mounts (Phase 9-bis"
echo "style) and skip real CUDA compute, documenting the gap honestly rather than forcing it."
