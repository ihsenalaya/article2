#!/usr/bin/env bash
# Tears down the confidential GPU VM and everything created alongside it
# (disk, NIC, public IP, NSG) by deleting the whole resource group -- the
# create script put everything in its own dedicated RG for exactly this
# reason (one clean, complete, verifiable teardown).
#
# Usage: ./teardown-cgpu-vm.sh <resource-group>
set -euo pipefail

RG="${1:?resource group required}"

# The Windows-native `az` CLI (invoked through WSL interop on this machine)
# emits trailing CRLF; command substitution keeps the \r, which silently
# broke this exact string comparison during the 2026-08-09 H100 session
# (a running, billed VM was reported as "does not exist"). Strip it.
EXISTS=$(az group exists --name "$RG" | tr -d '\r')
if [ "$EXISTS" != "true" ]; then
  echo "Resource group $RG does not exist -- nothing to tear down."
  exit 0
fi

echo "This will DESTROY every resource in $RG (VM, disk, NIC, public IP, NSG)."
echo "Real, current resources in this group:"
az resource list --resource-group "$RG" -o table
echo ""
read -r -p "Type the resource group name ($RG) to confirm and proceed: " CONFIRM
if [ "$CONFIRM" != "$RG" ]; then
  echo "Confirmation did not match -- aborted, nothing destroyed."
  exit 1
fi

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Deleting resource group $RG..."
az group delete --name "$RG" --yes --no-wait

echo "Deletion started (--no-wait). Verify completion and zero residual cost with:"
echo "  az group exists --name $RG"
echo "  az resource list --resource-group $RG   # should error \"ResourceGroupNotFound\" once done"
