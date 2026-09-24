#!/usr/bin/env bash
# Installs the NVIDIA driver on the AKS confidential H100 node
# (Standard_NCC40ads_H100_v5) and verifies GPU confidential-computing mode.
#
# Why not the NVIDIA GPU Operator: its driver container compiles the module
# on the node and derives the kernel version string by globbing
# /boot/vmlinuz-*. Azure confidential VMs boot from a signed Unified Kernel
# Image (/boot/efi/EFI/ubuntu/kernel.efi-*) with NO standalone vmlinuz, so
# that step fails with "Could not locate Linux kernel version string" and
# the DaemonSet crash-loops. Verified empirically, see EXPERIMENTS_LOG.md
# Phase 9.
#
# What works instead: Ubuntu ships PRE-BUILT, PRE-SIGNED nvidia kernel
# modules per kernel flavour, including the confidential `azure-fde`
# flavour. Nothing is compiled, so no vmlinuz is needed.
#
# Kernel version caveat (real, verified via apt-cache policy on 2026-08-01):
# the AKS GPU node image ships kernel 6.8.0-1061-azure-fde, but Ubuntu only
# publishes nvidia-570 prebuilt modules for 6.8.0-1062-azure-fde. Installing
# the `-azure-fde-6.8` meta-package pulls the matching 6.8.0-1062-azure-fde
# kernel as a dependency, hence the reboot below.
#
# Usage: KUBE_CONTEXT=<ctx> ./install-gpu-driver.sh
set -uo pipefail

KUBE_CONTEXT="${KUBE_CONTEXT:-article2-aks}"
DRIVER_BRANCH="${DRIVER_BRANCH:-570}"

GPU_NODE=$(kubectl --context "$KUBE_CONTEXT" get nodes -l "kubernetes.azure.com/agentpool=gpuh100" -o jsonpath='{.items[0].metadata.name}')
if [ -z "$GPU_NODE" ]; then
  echo "No GPU node found -- scale the gpuh100 node pool to 1 first." >&2
  exit 1
fi
echo "GPU node: $GPU_NODE"

echo "=== Step 1/3: installing driver + prebuilt signed modules (this pulls a newer kernel) ==="
kubectl --context "$KUBE_CONTEXT" debug node/"$GPU_NODE" --image=ubuntu:24.04 -q -- \
  chroot /host bash -c "
    set -x
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y \
      nvidia-driver-${DRIVER_BRANCH}-server-open \
      linux-modules-nvidia-${DRIVER_BRANCH}-server-open-azure-fde-6.8
    echo 'INSTALL_EXIT='\$?
    uname -r
  " || true

echo ""
echo "=== Step 2/3: rebooting the node to boot the kernel the modules were built for ==="
kubectl --context "$KUBE_CONTEXT" debug node/"$GPU_NODE" --image=ubuntu:24.04 -q -- \
  chroot /host bash -c 'systemctl reboot' || true

echo "Waiting for $GPU_NODE to come back Ready..."
for i in $(seq 1 60); do
  STATUS=$(kubectl --context "$KUBE_CONTEXT" get node "$GPU_NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
  if [ "$STATUS" = "True" ]; then
    # Ready can flap True right before the reboot actually takes effect; require it twice, spaced.
    sleep 10
    STATUS2=$(kubectl --context "$KUBE_CONTEXT" get node "$GPU_NODE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null)
    if [ "$STATUS2" = "True" ] && [ "$i" -gt 3 ]; then
      echo "Node Ready again after ~$((i * 10))s"
      break
    fi
  fi
  sleep 10
done

echo ""
echo "=== Step 3/3: verification (real output, never assumed) ==="
kubectl --context "$KUBE_CONTEXT" debug node/"$GPU_NODE" --image=ubuntu:24.04 -q -- \
  chroot /host bash -c '
    echo "--- kernel ---"; uname -r
    echo "--- nvidia devices ---"; ls -la /dev/nvidia* 2>&1
    echo "--- nvidia-smi ---"; nvidia-smi 2>&1 | head -15
    echo "--- driver version ---"; nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>&1
    echo "--- CONFIDENTIAL COMPUTE MODE ---"; nvidia-smi conf-compute -f 2>&1
    echo "--- CC environment ---"; nvidia-smi conf-compute -e 2>&1
  ' || true

echo ""
echo "Done. Report exactly what the verification printed above -- if CC status is not ON,"
echo "say so plainly rather than claiming confidential GPU execution."
