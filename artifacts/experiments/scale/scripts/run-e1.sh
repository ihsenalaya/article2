#!/usr/bin/env bash
# E1: steady-state scale (Task 08, experiment protocol section 10). N in
# {1,10,50,100}, n=3 repetitions per N (documented scope decision --
# experiment protocol prefers n=5; reduced under real time constraints on a
# single live billed cluster running many experiments serially).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/e1-steady-state.jsonl"
: > "$OUT"

declare -A TIMEOUTS=( [1]="60s" [10]="90s" [50]="180s" [100]="300s" )

for n in 1 10 50 100; do
  for rep in 1 2 3; do
    run_id="e1-n${n}-rep${rep}-$RANDOM"
    echo "[e1] N=$n rep=$rep run_id=$run_id"
    out_path="$(run_scale_job "$n" "$n" "$run_id" "${TIMEOUTS[$n]}")"
    if [ "$out_path" = "FAILED" ] || [ ! -f "$out_path" ]; then
      echo "[e1]   FAILED" >&2
      python3 -c "
import json
print(json.dumps({'n': $n, 'rep': $rep, 'run_id': '$run_id', 'outcome': 'job_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
      cleanup_scale_run "$run_id"
      continue
    fi
    python3 -c "
import json
with open('$out_path') as f:
    d = json.load(f)
n_converged = sum(1 for r in d['records'] if r['outcome'] == 'converged')
n_timed_out = sum(1 for r in d['records'] if r['outcome'] == 'timed_out')
n_failed = sum(1 for r in d['records'] if r['outcome'].startswith('failed'))
ready_times = [r['submit_to_ready_seconds'] for r in d['records'] if r['outcome'] == 'converged']
# metrics_samples is null (not []) when convergence happens before the
# first metrics-interval tick (2s) ever fires -- a real, expected outcome
# for small/fast N, not a bug in the generator.
samples = d['metrics_samples'] or []
cpu_op = [m['operator_cpu_milli'] for m in samples]
mem_op = [m['operator_mem_bytes'] for m in samples]
cpu_ag = [m['agent_cpu_milli'] for m in samples]
mem_ag = [m['agent_mem_bytes'] for m in samples]
rec = {
    'n': $n, 'rep': $rep, 'run_id': '$run_id',
    'n_converged': n_converged, 'n_timed_out': n_timed_out, 'n_failed': n_failed,
    'convergence_rate': n_converged / d['n'],
    'ready_time_mean': (sum(ready_times) / len(ready_times)) if ready_times else None,
    'ready_time_max': max(ready_times) if ready_times else None,
    'ready_time_min': min(ready_times) if ready_times else None,
    'operator_cpu_milli_max': max(cpu_op) if cpu_op else None,
    'operator_mem_bytes_max': max(mem_op) if mem_op else None,
    'agent_cpu_milli_max': max(cpu_ag) if cpu_ag else None,
    'agent_mem_bytes_max': max(mem_ag) if mem_ag else None,
    'n_metrics_samples': len(samples),
    'outcome': 'success',
    'git_commit': '$GIT_SHA',
}
print(json.dumps(rec))
" >> "$OUT"
    cleanup_scale_run "$run_id"
    sleep 3
  done
done

echo "[e1] done, $(wc -l < "$OUT") records in $OUT"
