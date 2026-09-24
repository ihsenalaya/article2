#!/usr/bin/env bash
# F4: event-rate curve (Task 09, experiment protocol section 11). Rate is
# varied by CONCURRENT WORKERS inside one ON pod (1/2/4/8), never by
# injecting sleeps between operations -- an achieved-throughput sweep via
# genuine parallelism, not a sleep-throttled generator, per the master
# prompt's explicit warning against "a misleading microseconds/event
# number from a rate-limited benchmark where wall-clock duration is fixed
# by the generator." Only the exec operation is swept (the "important"
# microbenchmark, and the one with the highest per-op cost, so it is the
# one most likely to reveal a rate-dependent loss curve on a 2-vCPU node).
# n=3 reps per concurrency tier.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/f4-rate-curve.jsonl"
: > "$OUT"

OP=exec
N_PER_WORKER=1500
CONCURRENCIES=(1 2 4 8)
REPS=3

for c in "${CONCURRENCIES[@]}"; do
  for rep in 1 2 3; do
    name="f4-c${c}-rep${rep}-$RANDOM"
    echo "[f4] concurrency=$c rep=$rep run_id=$name"
    create_on_pod "$name" || { echo "[f4]   setup failed" >&2; cleanup_pod "$name"; continue; }
    result="$(run_workload "$name" "$OP" "$N_PER_WORKER" "$c")"
    echo "[f4]   waiting 35s for evidence emission tick..."
    sleep 35
    evidence="$(get_evidence_counters "$name")"
    cleanup_pod "$name"

    if [ "$result" = "FAILED" ]; then
      python3 -c "
import json
print(json.dumps({'op': '$OP', 'concurrency': $c, 'rep': $rep, 'run_id': '$name', 'outcome': 'workload_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
      continue
    fi

    echo "$result" > /tmp/f4-result.json
    echo "$evidence" > /tmp/f4-evidence.json
    python3 -c "
import json
with open('/tmp/f4-result.json') as f: r = json.load(f)
with open('/tmp/f4-evidence.json') as f: ev = json.load(f)
rec = {
    'op': '$OP', 'concurrency': $c, 'rep': $rep, 'run_id': '$name',
    'outcome': 'success', 'git_commit': '$GIT_SHA',
    'n_per_worker': $N_PER_WORKER,
    'total_ops': r.get('total_ops', r.get('n_completed')),
    'total_errors': r.get('total_errors', r.get('n_errors')),
    'wall_seconds': r['wall_seconds'],
    'cpu_total_seconds': r.get('cpu_total_seconds'),
    'agg_ops_per_second': r.get('agg_ops_per_second', r.get('ops_per_second')),
    'drop_count': ev.get('dropCount'),
    'events_dropped_since_last_evidence': ev.get('eventsDroppedSinceLastEvidence'),
    'incorporated_count': ev.get('incorporatedCount'),
}
print(json.dumps(rec))
" >> "$OUT"
    sleep 2
  done
done

echo "[f4] done, $(wc -l < "$OUT") records in $OUT"
