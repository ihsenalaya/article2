#!/usr/bin/env bash
# E2: submission concurrency (Task 08, experiment protocol section 10). Fixed
# N=50 decisions, submitted at three numerically-defined concurrency
# levels (1, 10, 25 concurrent in-flight submissions), n=3 repetitions
# per level. Reports p50/p95/p99 of submit->accepted, submit->policy-
# created, submit->PolicyReady computed over the pooled per-decision
# records across all reps of a level (not per-run means), per master
# prompt's "distributions" requirement.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/e2-concurrency.jsonl"
: > "$OUT"

N=50
CONVERGE_TIMEOUT="180s"

for concurrency in 1 10 25; do
  for rep in 1 2 3; do
    run_id="e2-c${concurrency}-rep${rep}-$RANDOM"
    echo "[e2] concurrency=$concurrency rep=$rep run_id=$run_id"
    out_path="$(run_scale_job "$N" "$concurrency" "$run_id" "$CONVERGE_TIMEOUT")"
    if [ "$out_path" = "FAILED" ] || [ ! -f "$out_path" ]; then
      echo "[e2]   FAILED" >&2
      python3 -c "
import json
print(json.dumps({'concurrency': $concurrency, 'n': $N, 'rep': $rep, 'run_id': '$run_id', 'outcome': 'job_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
      cleanup_scale_run "$run_id"
      continue
    fi
    python3 -c "
import json
with open('$out_path') as f:
    d = json.load(f)
rec = {
    'concurrency': $concurrency, 'n': $N, 'rep': $rep, 'run_id': '$run_id',
    'outcome': 'success', 'git_commit': '$GIT_SHA',
    'records': d['records'],
}
print(json.dumps(rec))
" >> "$OUT"
    cleanup_scale_run "$run_id"
    sleep 3
  done
done

echo "[e2] done, $(wc -l < "$OUT") lines in $OUT"
