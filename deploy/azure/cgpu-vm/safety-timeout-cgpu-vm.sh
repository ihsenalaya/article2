#!/usr/bin/env bash
# Safety-net watchdog for the confidential GPU VM (rule 5): auto-deletes its
# resource group after N hours if nobody remembers to tear it down manually.
# Not the primary mechanism -- insurance against a forgotten $8.82/hour VM.
#
# Usage: nohup ./safety-timeout-cgpu-vm.sh <resource-group> <hours> > /tmp/cgpu-safety-timeout.log 2>&1 &
#        echo $! > /tmp/cgpu-safety-timeout.pid
# Cancel before it fires: kill "$(cat /tmp/cgpu-safety-timeout.pid)"
set -uo pipefail

RG="${1:?resource group required}"
HOURS="${2:?duration in hours required, e.g. 4}"

# Real incident (Phase 9-bis -> 9-ter, see EXPERIMENTS_LOG.md): the AKS
# safety-timeout script fired hours later using a DIFFERENT identity (the
# automation service principal) which turned out to have zero rights on
# this VM's resource group -- it failed loudly there, but nothing stopped
# it from failing *silently* here too if the active `az` session at fire
# time can't touch $RG. Check up front, at arm time, so a permissions
# problem is caught immediately instead of discovered hours later when the
# watchdog actually needs to fire.
if ! az group show --name "$RG" >/dev/null 2>&1; then
  echo "FATAL: the current az CLI identity cannot read resource group $RG -- refusing to arm a" >&2
  echo "safety timeout that would silently fail to fire. Run 'az account show' to check identity," >&2
  echo "'az login' if needed, then re-arm." >&2
  exit 1
fi

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Safety timeout armed for ${HOURS}h on $RG. PID=$$ (identity check passed: $(az account show --query user.name -o tsv 2>/dev/null))"
SECONDS_TO_WAIT=$(python3 -c "print(int(float(\"$HOURS\") * 3600))")
sleep "$SECONDS_TO_WAIT"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Timeout elapsed. Deleting resource group $RG..."
if ! az group show --name "$RG" >/dev/null 2>&1; then
  echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) FATAL: identity can no longer read $RG (session expired/changed" >&2
  echo "since arming) -- cannot delete. Manual intervention required NOW: check az account show," >&2
  echo "re-login, and run 'az group delete --name $RG --yes' yourself." >&2
  exit 1
fi
az group delete --name "$RG" --yes --no-wait
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Safety timeout completed: deletion of $RG requested."
