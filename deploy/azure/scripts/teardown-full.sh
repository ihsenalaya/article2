#!/usr/bin/env bash
# Full teardown: destroys every Azure resource this project created (Phase
# 10). Irreversible -- requires typing the resource group name back to
# confirm, same spirit as the mandatory Phase 8 human checkpoint before
# creation.
#
# Usage: ./teardown-full.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../terraform"

RG_NAME=$(terraform output -raw resource_group_name 2>/dev/null || echo "")
if [ -z "$RG_NAME" ]; then
  echo "Could not read resource_group_name from terraform state -- is this the right directory, and has 'terraform apply' ever run?" >&2
  exit 1
fi

echo "This will DESTROY every Azure resource in $RG_NAME, including all"
echo "results not yet copied out. Type the resource group name to confirm:"
read -r CONFIRM
if [ "$CONFIRM" != "$RG_NAME" ]; then
  echo "Confirmation did not match ($RG_NAME) -- aborted, nothing destroyed."
  exit 1
fi

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Running terraform destroy on $RG_NAME..."
terraform destroy -auto-approve
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Teardown complete."
