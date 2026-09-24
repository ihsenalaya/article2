#!/usr/bin/env bash
# Downloads model WEIGHTS ONLY from the Azure AI Foundry model catalog --
# never used as a hosted inference endpoint (inference is always
# self-hosted on our own AKS pods, per the mission's non-negotiable rule).
#
# Reuse-if-exists-else-fetch: if the target directory already has a
# non-empty weights file, this is a no-op (idempotent, safe to re-run from
# the safety-timeout watchdog or a fresh shell without re-downloading
# multi-GB weights every time).
#
# Usage: ./fetch-foundry-model.sh <model-name> <model-version> <dest-dir>
# Example: ./fetch-foundry-model.sh azureml://registries/azureml/models/Phi-3.5-mini-instruct 1 /mnt/foundry-models/phi-3.5-mini
set -euo pipefail

MODEL_URI="${1:?model registry URI required, e.g. azureml://registries/azureml/models/Phi-3.5-mini-instruct}"
MODEL_VERSION="${2:?model version required}"
DEST_DIR="${3:?destination directory required}"
RESOURCE_GROUP="${RESOURCE_GROUP:?set RESOURCE_GROUP to the terraform-created RG name (see: terraform output resource_group_name)}"
WORKSPACE_NAME="${WORKSPACE_NAME:?set WORKSPACE_NAME to the Foundry project name (see: terraform output foundry_project_name)}"

mkdir -p "$DEST_DIR"

if find "$DEST_DIR" -type f -size +1M | grep -q .; then
  echo "Weights already present in $DEST_DIR (found a file >1MB) -- skipping download."
  echo "Delete $DEST_DIR and re-run to force a re-fetch."
  exit 0
fi

echo "Downloading $MODEL_URI (version $MODEL_VERSION) into $DEST_DIR ..."
az ml model download \
  --name "$(basename "$MODEL_URI")" \
  --version "$MODEL_VERSION" \
  --registry-name azureml \
  --download-path "$DEST_DIR" \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$WORKSPACE_NAME"

echo "Done. Contents of $DEST_DIR:"
find "$DEST_DIR" -type f -exec ls -lh {} \;

echo "REMINDER: these weights are for self-hosted inference on our own AKS"
echo "pods only. Do not create or call an Azure-hosted inference endpoint"
echo "for this model -- that would violate the mission's non-negotiable rule."
