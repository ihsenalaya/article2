#!/usr/bin/env bash
# Task 10: enable real BPF-LSM enforcement on the worker node. Deliberately
# NOT run automatically by bootstrap-cluster.sh -- this reboots a live VM
# (a brief outage of any pods on it) and is a meaningful behavioral change
# (audit-only -> real kernel-level enforcement capability), so it is an
# explicit, separate, opt-in step, matching how it required explicit user
# confirmation the first time this campaign did it live.
#
# Only touches the WORKER node. The control-plane node is deliberately left
# on audit-only (an intentional within-cluster comparison point -- see
# artifacts/experiments/bpf-lsm/summary.md).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

tf_output() {
  terraform -chdir="$TF_DIR" output -raw "$1"
}

RESOURCE_GROUP="$(tf_output resource_group_name)"
WORKER_VM_NAME="${WORKER_VM_NAME:-vm-a2-cpucampaign-20260813-worker}"
LSM_LIST="${LSM_LIST:-lockdown,capability,landlock,yama,apparmor,bpf}"

echo "=== verifying CONFIG_BPF_LSM=y (kernel support) ==="
az vm run-command invoke -g "$RESOURCE_GROUP" -n "$WORKER_VM_NAME" \
  --command-id RunShellScript \
  --scripts "grep CONFIG_BPF_LSM /boot/config-\$(uname -r)"

echo "=== checking current active LSM list ==="
CURRENT_LSM="$(az vm run-command invoke -g "$RESOURCE_GROUP" -n "$WORKER_VM_NAME" \
  --command-id RunShellScript --scripts "cat /sys/kernel/security/lsm" \
  --query "value[0].message" -o tsv 2>/dev/null | grep -o '[a-z,]*bpf[a-z,]*' || true)"

if echo "$CURRENT_LSM" | grep -q "bpf"; then
  echo "bpf already active in /sys/kernel/security/lsm -- nothing to do."
  exit 0
fi

echo "=== bpf not active; updating GRUB and rebooting ==="
echo "*** This reboots $WORKER_VM_NAME -- any pods scheduled on it will"
echo "*** restart. Proceeding in 5s (Ctrl-C to abort)."
sleep 5

# IMPORTANT: GRUB_CMDLINE_LINUX, not _DEFAULT. This Azure Ubuntu cloud
# image's /etc/default/grub.d/50-cloudimg-settings.cfg unconditionally
# resets GRUB_CMDLINE_LINUX_DEFAULT="" on every update-grub (sourced AFTER
# /etc/default/grub), silently discarding anything placed there -- found
# the hard way in Task 10 (first reboot attempt had NO lsm= parameter at
# all in /proc/cmdline afterward, not even the "quiet splash" that WAS in
# the edited file). GRUB_CMDLINE_LINUX is APPENDED to by that same file,
# not overwritten, and survives.
az vm run-command invoke -g "$RESOURCE_GROUP" -n "$WORKER_VM_NAME" \
  --command-id RunShellScript \
  --scripts "set -e
if ! grep -q 'lsm=' /etc/default/grub; then
  sed -i 's/^GRUB_CMDLINE_LINUX=\"\"/GRUB_CMDLINE_LINUX=\"lsm=${LSM_LIST}\"/' /etc/default/grub
fi
grep GRUB_CMDLINE_LINUX /etc/default/grub
update-grub
"

az vm restart -g "$RESOURCE_GROUP" -n "$WORKER_VM_NAME"

echo "=== waiting for VM to report running ==="
for _ in $(seq 1 40); do
  state="$(az vm get-instance-view -g "$RESOURCE_GROUP" -n "$WORKER_VM_NAME" \
    --query "instanceView.statuses[?starts_with(code,'PowerState')].code" -o tsv)"
  [ "$state" = "PowerState/running" ] && break
  sleep 15
done

echo "=== verifying bpf is now active (the actual runtime condition, not just CONFIG_BPF_LSM=y) ==="
az vm run-command invoke -g "$RESOURCE_GROUP" -n "$WORKER_VM_NAME" \
  --command-id RunShellScript --scripts "cat /sys/kernel/security/lsm"

echo
echo "Done. Restart the runtime-guard-agent DaemonSet pod on this node if it"
echo "was already running before this reboot, so it re-detects enforce mode:"
echo "  kubectl -n runtime-guard-agent-system delete pod -l app=runtime-guard-agent --field-selector spec.nodeName=$WORKER_VM_NAME"
