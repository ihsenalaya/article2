#!/usr/bin/env bash
# GPU / confidential-computing validation for an H100 worker node.
#
# MUST NOT be run against real hardware without explicit user authorization
#. It is safe to read, safe to shellcheck,
# safe to point at a plain non-GPU node (every GPU check below is written to
# report its real absence rather than fail silently), but running it IS the
# kind of "prepare confidential-mode validation scripts" activity the H100
# safety gate explicitly allows -- actually invoking it against a live H100
# is provisioning-adjacent and gated behind the same authorization as
# TASK-16/17.
#
# Labels claimed by join-worker.sh (accelerator=nvidia-h100,
# confidential-compute=true) do NOT prove these properties -- only this
# script's actual output does.
#
# Usage: ./validate-gpu-worker.sh <node-name> <target-public-ip> <ssh-user> [ssh-key-path] [out-dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_DIR="$TF_DIR/.run"

NODE_NAME="${1:?node name required}"
TARGET_IP="${2:?target node public/reachable IP required}"
SSH_USER="${3:?ssh user required}"
SSH_KEY="${4:-$HOME/.ssh/id_ed25519}"
OUT_DIR="${5:-$RUN_DIR/validation-gpu-${NODE_NAME}}"

mkdir -p "$OUT_DIR"

ssh_opts=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY")
remote_capture() {
  local name="$1"
  shift
  # Do not fail the whole script on a single missing tool (e.g. nvidia-smi
  # absent on a non-GPU dry-run target) -- capture the real failure instead,
  # per the experiment protocol: report NOT MEASURED / SKIPPED, never fabricate PASS.
  ssh "${ssh_opts[@]}" "${SSH_USER}@${TARGET_IP}" "$@" > "$OUT_DIR/${name}.out" 2> "$OUT_DIR/${name}.err" || \
    echo "command failed or tool absent, see ${name}.err" >> "$OUT_DIR/${name}.out"
}

echo "=== GPU presence ==="
remote_capture "nvidia-smi" "nvidia-smi"

echo "=== NVIDIA confidential-computing feature state (H100 CC-ON mode) ==="
remote_capture "nvidia-conf-compute" "nvidia-smi conf-compute -f"

echo "=== SEV-SNP activation in kernel log (Azure NCC-series confidential VM) ==="
remote_capture "dmesg-sev" "sudo dmesg | grep -i sev"

echo "=== active LSMs (must include a BPF-capable LSM for device-access mediation, A19) ==="
remote_capture "lsm" "cat /sys/kernel/security/lsm 2>/dev/null || true"

echo "=== BPF-LSM feature probe on this exact kernel/image ==="
remote_capture "bpf-lsm-feature-probe" "sudo bpftool feature probe kernel unprivileged"

echo "=== NVIDIA driver / CUDA versions actually installed (verify against expectations, do not assume) ==="
remote_capture "nvidia-driver-version" "cat /proc/driver/nvidia/version 2>/dev/null || true"
remote_capture "cuda-version" "nvcc --version 2>/dev/null || nvidia-smi --query-gpu=driver_version,cuda_version --format=csv 2>/dev/null || true"

cat > "$OUT_DIR/summary.txt" <<SUMMARY
GPU/confidential-computing validation for '$NODE_NAME' ($TARGET_IP)

Read each *.out / *.err pair before drawing any conclusion. In particular:
- nvidia-smi failing or absent => REAL H100 ENFORCEMENT NOT AVAILABLE, do not
  proceed to claim GPU-backed results.
- 'nvidia-smi conf-compute -f' not reporting the GPU in a protected/CC-ON
  state => confidential-computing mode is NOT active; report this explicitly,
  do not describe subsequent results as confidential-computing results.
- dmesg-sev empty => SEV-SNP did not activate; the VM is not running in
  confidential mode regardless of the SKU name used to create it.
- lsm output missing "bpf" => device-access mediation (A19) cannot be
  enforced via BPF-LSM on this kernel/image; report SKIPPED -- CAPABILITY
  NOT AVAILABLE, never substitute audit-only detection and call it enforcement.
SUMMARY

cat "$OUT_DIR/summary.txt"
