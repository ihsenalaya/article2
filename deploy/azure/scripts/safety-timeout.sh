#!/usr/bin/env bash
# Safety-net watchdog (rule 5): a last-resort automatic teardown of the GPU
# node pool if nobody remembers to run scale-down-gpu.sh manually after a
# measurement campaign. Not the primary mechanism -- just insurance against
# a forgotten GPU racking up cost overnight.
#
# Logs in as the dedicated automation service principal (fetched from our
# own Key Vault while the operator's interactive `az login` session is
# still active) so the watchdog keeps working even if the launching
# terminal's session expires hours later.
#
# Usage: nohup ./safety-timeout.sh <hours> > /tmp/safety-timeout.log 2>&1 &
#        echo $! > /tmp/safety-timeout.pid
# Cancel before it fires: kill "$(cat /tmp/safety-timeout.pid)"
set -euo pipefail

# Resolve this script's own directory ONCE, before any `cd` -- a real bug
# found the hard way: this script used to `cd "$TERRAFORM_DIR"` and then,
# hours later, re-evaluate `dirname "${BASH_SOURCE[0]}"` (a path that was
# relative to the ORIGINAL launch directory) against that new cwd, silently
# resolving to a nonexistent path and failing with
# "scale-down-gpu.sh: No such file or directory" right when it mattered
# most (the actual scale-down after the sleep). See EXPERIMENTS_LOG.md
# Phase 9-ter.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

HOURS="${1:?duration in hours required, e.g. 6}"
TERRAFORM_DIR="$(cd "$SCRIPT_DIR/../terraform" && pwd)"

cd "$TERRAFORM_DIR"
KEY_VAULT_NAME=$(terraform output -raw key_vault_name)

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Safety timeout armed for ${HOURS}h. PID=$$"

CLIENT_ID=$(az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name automation-sp-client-id --query value -o tsv)
CLIENT_SECRET=$(az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name automation-sp-client-secret --query value -o tsv)
TENANT_ID=$(az keyvault secret show --vault-name "$KEY_VAULT_NAME" --name automation-sp-tenant-id --query value -o tsv)

SECONDS_TO_WAIT=$(python3 -c "print(int(float(\"$HOURS\") * 3600))")
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Sleeping ${SECONDS_TO_WAIT}s ($HOURS hours)..."
sleep "$SECONDS_TO_WAIT"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Timeout elapsed. Logging in as automation SP and scaling down GPU pool..."
az login --service-principal -u "$CLIENT_ID" -p "$CLIENT_SECRET" --tenant "$TENANT_ID" >/dev/null

"$SCRIPT_DIR/scale-down-gpu.sh"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Safety timeout completed: GPU pool scaled down automatically."
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) NOTE: this shell's az CLI session is now the automation SP,"
echo "not your interactive user -- run 'az login' again before any command that needs your own"
echo "identity's permissions (this SP is intentionally scoped to only this one resource group)."
