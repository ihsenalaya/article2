#!/usr/bin/env bash
# A3: concurrency stress. Concurrency levels 1/10/50, REPS repetitions each
# (default 5 -- "sufficient repetitions", not individually specified by the
# experiment protocol for A3; documented honestly as a scope choice under real
# time constraints, see exclusions.md/summary.md).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

REPS="${1:-5}"
OUT="$PWD/../raw/a3-concurrency.jsonl"
: > "$OUT"

for conc in 1 10 50; do
  for rep in $(seq 1 "$REPS"); do
    echo "[a3] concurrency=$conc rep=$rep/$REPS"
    pids=()
    for j in $(seq 1 "$conc"); do
      run_name="closure-a3-c${conc}-r${rep}-$(printf '%03d' "$j")-$RANDOM"
      run_trial "$run_name" "a3-concurrency-${conc}" 0 "$OUT" &
      pids+=($!)
    done
    for pid in "${pids[@]}"; do
      wait "$pid"
    done
  done
done
echo "[a3] done, $(wc -l < "$OUT") records in $OUT"
