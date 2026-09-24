#!/usr/bin/env bash
# Reruns ONLY this microbenchmark (the BPF-LSM enforcement-path overhead
# experiment). Does not touch any other RuntimeGuard experiment or result.
#
# Prerequisites:
#   - The cpu-campaign-20260813 Azure cluster is up (deploy/azure/cpu-campaign-20260813)
#     with RuntimeGuard deployed and the worker's BPF-LSM active
#     (scripts/enable-bpf-lsm.sh already run) -- see ../../DEBUG-HANDOFF.md and
#     deploy/azure/cpu-campaign-20260813/scripts/ for how to bring this up from
#     scratch if it does not already exist.
#   - The ebpf-agent DaemonSet is running the image built from this session's
#     agent.bpf.c/common.h/loader.go/cmd/agent/main.go changes (benchmark_mode
#     support + --benchmark-mode-enabled), deployed with that flag set to
#     "true" on the agent pod running on the worker node ONLY (see
#     manifests note in README.md's Environment section).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

MODE="${1:-full}"  # "smoke" for a 2-block sanity check, "full" for the real 30-block run

echo "=== setup: bench-pod + signed decision (enforce + ALLOW exec/file/network) ==="
eval "$(bash scripts/setup.sh)"

echo "=== running benchmark (mode=$MODE) ==="
python3 scripts/run_benchmark.py "$MODE"

echo "=== analyzing ==="
python3 analyze.py

echo "=== done. See paired_results.csv / summary.csv / validation/ ==="
