#!/usr/bin/env bash
# Fast, targeted teardown of JUST the confidential H100 GPU node pool --
# the single most expensive resource in this environment ($8.82/hour
# on-demand as of 2026-08-01, see EXPERIMENTS_LOG.md Phase 7). Leaves the
# AKS system pool, storage, and results intact so analysis can continue.
#
# This is what deploy/azure/scripts/safety-timeout.sh calls automatically,
# and what a human should call manually the moment a measurement campaign
# ends -- do not wait for the timeout as the primary mechanism.
#
# Usage: ./scale-down-gpu.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../terraform"

echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) Scaling down GPU node pool (enable_gpu_pool=false)..."
terraform apply -auto-approve -var enable_gpu_pool=false
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) GPU node pool removed. AKS system pool, storage, and results are untouched."
