#!/usr/bin/env bash
# A1: nominal cooperative case, n independent runs (default 30).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

N="${1:-30}"
OUT="$PWD/../raw/a1-nominal.jsonl"
: > "$OUT"

for i in $(seq 1 "$N"); do
  run_name="closure-a1-$(printf '%03d' "$i")-$RANDOM"
  echo "[a1] run $i/$N: $run_name"
  run_trial "$run_name" "a1-nominal" 0 "$OUT"
done
echo "[a1] done, $(wc -l < "$OUT") records in $OUT"
