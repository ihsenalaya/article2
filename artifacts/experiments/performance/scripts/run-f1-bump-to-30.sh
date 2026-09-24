#!/usr/bin/env bash
# Task 12 follow-up: bring file/network up to the same n=30 target exec
# already met (the original file/network n=20 was an explicitly
# documented scope reduction, not an error -- see exclusions.md; this
# closes that gap rather than leaving it). Appends blocks 21-30 to the
# SAME raw/f1-paired-blocks.jsonl (never truncates -- identical pattern
# to run-f1-resume.sh), using the exact same per-block methodology
# (randomized ON/OFF order, fresh pod/decision names every block) as
# run-f1.sh's original blocks 1-20.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/f1-paired-blocks.jsonl"

declare -A ITERS=( [file]=20000 [network]=5000 )

for op in file network; do
  n="${ITERS[$op]}"
  for block in $(seq 21 30); do
    suffix="$RANDOM"
    on_name="f1-${op}-on-b${block}-${suffix}"
    off_name="f1-${op}-off-b${block}-${suffix}"

    order=$((RANDOM % 2))
    echo "[f1-bump] op=$op block=$block/30 order=$([ $order -eq 0 ] && echo ON-first || echo OFF-first)"

    on_result="" off_result=""
    if [ "$order" -eq 0 ]; then
      create_on_pod "$on_name" || { echo "[f1-bump]   ON pod setup failed, skipping block" >&2; cleanup_pod "$on_name"; continue; }
      on_result="$(run_workload "$on_name" "$op" "$n")"
      cleanup_pod "$on_name"
      create_off_pod "$off_name" || { echo "[f1-bump]   OFF pod setup failed, skipping block" >&2; cleanup_pod "$off_name"; continue; }
      off_result="$(run_workload "$off_name" "$op" "$n")"
      cleanup_pod "$off_name"
    else
      create_off_pod "$off_name" || { echo "[f1-bump]   OFF pod setup failed, skipping block" >&2; cleanup_pod "$off_name"; continue; }
      off_result="$(run_workload "$off_name" "$op" "$n")"
      cleanup_pod "$off_name"
      create_on_pod "$on_name" || { echo "[f1-bump]   ON pod setup failed, skipping block" >&2; cleanup_pod "$on_name"; continue; }
      on_result="$(run_workload "$on_name" "$op" "$n")"
      cleanup_pod "$on_name"
    fi

    if [ "$on_result" = "FAILED" ] || [ "$off_result" = "FAILED" ]; then
      echo "[f1-bump]   workload exec FAILED (on=$on_result off=$off_result)" >&2
      python3 -c "
import json
print(json.dumps({'op': '$op', 'block': $block, 'order': $order, 'outcome': 'workload_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
      continue
    fi

    echo "$on_result" > /tmp/f1bump-on-result.json
    echo "$off_result" > /tmp/f1bump-off-result.json
    python3 -c "
import json
with open('/tmp/f1bump-on-result.json') as f: on = json.load(f)
with open('/tmp/f1bump-off-result.json') as f: off = json.load(f)
rec = {
    'op': '$op', 'block': $block, 'order': $order, 'outcome': 'success',
    'n': $n, 'git_commit': '$GIT_SHA',
    'on_wall_seconds': on['wall_seconds'], 'off_wall_seconds': off['wall_seconds'],
    'on_cpu_total_seconds': on['cpu_total_seconds'], 'off_cpu_total_seconds': off['cpu_total_seconds'],
    'on_usec_per_op': on['usec_per_op_cpu_total'], 'off_usec_per_op': off['usec_per_op_cpu_total'],
    'diff_usec_per_op': on['usec_per_op_cpu_total'] - off['usec_per_op_cpu_total'],
    'on_n_errors': on['n_errors'], 'off_n_errors': off['n_errors'],
}
print(json.dumps(rec))
" >> "$OUT"
  done
done

echo "[f1-bump] done. Total records now: $(wc -l < "$OUT")"
