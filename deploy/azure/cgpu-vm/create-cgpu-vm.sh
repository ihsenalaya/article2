#!/usr/bin/env bash
# Creates the confidential H100 GPU VM from the official Azure/az-cgpu-onboarding
# community gallery image (VMI) -- pre-validated, pre-signed NVIDIA driver +
# CUDA + Docker + local attestation verifier, sidestepping the 5 real driver
# install failures hit on the AKS-managed node pool path (see
# EXPERIMENTS_LOG.md Phase 9 / Phase 9-bis).
#
# MANDATORY HUMAN CHECKPOINT: do not run this script without having first
# stopped to summarize cost/duration and gotten explicit confirmation, per
# the mission's non-negotiable rule 6. This script itself also refuses to
# proceed without a typed confirmation, as a second safety layer.
#
# Usage: ./create-cgpu-vm.sh <resource-group> <vm-name> <region> <ssh-public-key-path>
# region must be eastus2 or westeurope (only regions this VMI is published to).
set -euo pipefail

RG="${1:?resource group required}"
VM_NAME="${2:?VM name required}"
REGION="${3:?region required (eastus2 or westeurope)}"
SSH_PUBKEY_PATH="${4:?path to SSH public key required}"
OWNER="${OWNER:-ihsen-alaya}"
TTL="${TTL:-12h}"

if [ "$REGION" != "eastus2" ] && [ "$REGION" != "westeurope" ]; then
  echo "region must be eastus2 or westeurope (only regions the cgpu VMI is published to), got: $REGION" >&2
  exit 1
fi

IMAGE_REF="/CommunityGalleries/cgpuimage-db870bae-5bcf-4120-9415-b841adef61d3/Images/cgpu-NCC-2404-base-image/versions/latest"
VM_SIZE="Standard_NCC40ads_H100_v5"

echo "=================================================================="
echo "About to create a REAL, BILLED confidential GPU VM:"
echo "  Resource group : $RG (region: $REGION)"
echo "  VM name        : $VM_NAME"
echo "  Size           : $VM_SIZE (~\$8.82/hour on-demand, eastus2 pricing verified 2026-08-01)"
echo "  Image          : official Azure/az-cgpu-onboarding VMI (cgpu-NCC-2404-base-image)"
echo "  Tags           : project=these-article2, owner=$OWNER, ttl=$TTL"
echo "=================================================================="
read -r -p "Type the VM name ($VM_NAME) to confirm and proceed: " CONFIRM
if [ "$CONFIRM" != "$VM_NAME" ]; then
  echo "Confirmation did not match -- aborted, nothing created."
  exit 1
fi

az group create --name "$RG" --location "$REGION" \
  --tags project=these-article2 owner="$OWNER" ttl="$TTL" purpose=confidential-gpu-vmi \
  -o none

az vm create \
  --resource-group "$RG" \
  --name "$VM_NAME" \
  --location "$REGION" \
  --image "$IMAGE_REF" \
  --public-ip-sku Standard \
  --admin-username azureuser \
  --ssh-key-values "$SSH_PUBKEY_PATH" \
  --security-type ConfidentialVM \
  --os-disk-security-encryption-type VMGuestStateOnly \
  --enable-secure-boot true \
  --enable-vtpm true \
  --size "$VM_SIZE" \
  --os-disk-size-gb 100 \
  --tags project=these-article2 owner="$OWNER" ttl="$TTL" purpose=confidential-gpu-vmi \
  --accept-term

echo ""
echo "=== opening 6443 for the current caller IP only (k8s API, closed by default on this VMI) ==="
MY_IP="$(curl -s https://ifconfig.me)"
az network nsg rule create \
  --resource-group "$RG" \
  --nsg-name "${VM_NAME}NSG" \
  --name allow-k8s-api-myip \
  --priority 300 \
  --access Allow \
  --protocol Tcp \
  --direction Inbound \
  --source-address-prefixes "${MY_IP}/32" \
  --source-port-ranges '*' \
  --destination-port-ranges 6443 \
  --destination-address-prefixes '*' \
  -o none

echo ""
echo "VM created. Public IP:"
az vm show -d --resource-group "$RG" --name "$VM_NAME" --query publicIps -o tsv
