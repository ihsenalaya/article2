#!/usr/bin/env bash
# Task 12 follow-up: F4's OFF-condition counterpart. run-f4.sh only ever
# swept the ON condition (an explicitly documented gap: "not decomposed
# into RuntimeGuard's own contention cost vs. generic Linux fork/exec
# contention cost" -- see exclusions.md). This script runs the SAME
# concurrency sweep against UNTRACKED pods, so the two curves together
# let per-op-cost-under-contention be decomposed into "RuntimeGuard's own
# marginal contention cost" (ON minus OFF, both under the same node CPU
# pressure) versus "generic Linux fork/exec contention on a 2-vCPU node"
# (OFF alone, present regardless of RuntimeGuard).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/f4-rate-curve-off.jsonl"
: > "$OUT"

OP=exec
N_PER_WORKER=1500
CONCURRENCIES=(1 2 4 8)
REPS=3

for c in "${CONCURRENCIES[@]}"; do
  for rep in 1 2 3; do
    name="f4off-c${c}-rep${rep}-$RANDOM"
    echo "[f4-off] concurrency=$c rep=$rep run_id=$name"
    # settle_seconds mirrors create_on_pod's mint_and_authorize wall-clock
    # delay (see lib.sh's own comment on create_off_pod) -- kept identical
    # across the ON and OFF sweeps so neither is measured "colder".
    create_off_pod "$name" 3 || { echo "[f4-off]   setup failed" >&2; cleanup_pod "$name"; continue; }
    result="$(run_workload "$name" "$OP" "$N_PER_WORKER" "$c")"
    cleanup_pod "$name"

    if [ "$result" = "FAILED" ]; then
      python3 -c "
import json
print(json.dumps({'op': '$OP', 'condition': 'off', 'concurrency': $c, 'rep': $rep, 'run_id': '$name', 'outcome': 'workload_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
      continue
    fi

    echo "$result" > /tmp/f4off-result.json
    python3 -c "
import json
with open('/tmp/f4off-result.json') as f: r = json.load(f)
rec = {
    'op': '$OP', 'condition': 'off', 'concurrency': $c, 'rep': $rep, 'run_id': '$name',
    'outcome': 'success', 'git_commit': '$GIT_SHA',
    'n_per_worker': $N_PER_WORKER,
    'total_ops': r.get('total_ops', r.get('n_completed')),
    'total_errors': r.get('total_errors', r.get('n_errors')),
    'wall_seconds': r['wall_seconds'],
    'cpu_total_seconds': r.get('cpu_total_seconds'),
    'agg_ops_per_second': r.get('agg_ops_per_second', r.get('ops_per_second')),
}
print(json.dumps(rec))
" >> "$OUT"
    sleep 2
  done
done

echo "[f4-off] done, $(wc -l < "$OUT") records in $OUT"
