#!/usr/bin/env bash
# A2: policy-readiness stress. Delays 0/50/250/1000ms, N runs each (default 20).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

N="${1:-20}"
OUT="$PWD/../raw/a2-readiness-stress.jsonl"
: > "$OUT"

for delay in 0 50 250 1000; do
  for i in $(seq 1 "$N"); do
    run_name="closure-a2-d${delay}-$(printf '%03d' "$i")-$RANDOM"
    echo "[a2] delay=${delay}ms run $i/$N: $run_name"
    run_trial "$run_name" "a2-delay-${delay}ms" "$delay" "$OUT"
  done
done
echo "[a2] done, $(wc -l < "$OUT") records in $OUT"
