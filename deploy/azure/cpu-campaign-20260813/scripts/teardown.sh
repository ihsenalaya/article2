#!/usr/bin/env bash
# Experiment protocol section 19 (cloud teardown): show a destroy plan for human
# review before actually destroying anything, and only ever touch this
# campaign's own dedicated Terraform state/resource group.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== terraform plan -destroy (review before confirming) ==="
terraform -chdir="$TF_DIR" plan -destroy -out="$TF_DIR/.run/destroy.tfplan"

echo
echo "Review the plan above. It must affect ONLY resources in the"
echo "rg-a2-cpucampaign-20260813 resource group (VMs, disks, NICs, IPs, VNet,"
echo "NSG, subnet, auto-shutdown schedules) and nothing else."
echo
read -r -p "Type 'destroy' to apply this plan: " confirm
if [ "$confirm" != "destroy" ]; then
  echo "Aborted, nothing destroyed."
  exit 1
fi

terraform -chdir="$TF_DIR" apply "$TF_DIR/.run/destroy.tfplan"
