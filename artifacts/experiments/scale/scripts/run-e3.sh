#!/usr/bin/env bash
# E3: 500-policy case (Task 08, experiment protocol section 10). Literal N=500
# is attempted, not substituted -- the experiment protocol requires re-running
# the 500-policy scenario and, if it fails, RCA from cluster-side
# evidence rather than assuming/blaming the client path. This cluster's
# schedulable capacity is a single worker node with a hard 110-pod limit
# (control-plane is tainted NoSchedule -- see artifacts/azure/environment.md),
# so partial/failed convergence at N=500 is an expected, reportable
# cluster-capacity finding, not a script bug. Each rep additionally
# captures FailedScheduling event counts and pod-phase counts as direct
# cluster-side RCA evidence for whatever the generator's own per-decision
# outcomes show.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/e3-500-policy.jsonl"
: > "$OUT"

N=500
CONCURRENCY=50
CONVERGE_TIMEOUT="300s"

for rep in 1 2 3; do
  run_id="e3-rep${rep}-$RANDOM"
  echo "[e3] rep=$rep run_id=$run_id"
  out_path="$(run_scale_job "$N" "$CONCURRENCY" "$run_id" "$CONVERGE_TIMEOUT")"
  if [ "$out_path" = "FAILED" ] || [ ! -f "$out_path" ]; then
    echo "[e3]   FAILED (job-level)" >&2
    python3 -c "
import json
print(json.dumps({'n': $N, 'rep': $rep, 'run_id': '$run_id', 'outcome': 'job_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
    cleanup_scale_run "$run_id"
    continue
  fi

  # Cluster-side RCA evidence, captured BEFORE cleanup deletes anything.
  rca_path="$PWD/../raw/${run_id}.rca.txt"
  {
    echo "=== FailedScheduling event count for run_id=$run_id ==="
    kubectl -n "$NS" get events --field-selector reason=FailedScheduling -o json 2>/dev/null \
      | python3 -c "import json,sys; d=json.load(sys.stdin); print(sum(1 for i in d['items'] if '$run_id' in i.get('involvedObject',{}).get('name','')))"
    echo "=== pod phase counts for run_id=$run_id ==="
    kubectl -n "$NS" get pods -l "scale-run=$run_id" --no-headers 2>/dev/null | awk '{print $3}' | sort | uniq -c
    echo "=== node pod capacity ==="
    kubectl get nodes -o json 2>/dev/null | python3 -c "
import json,sys
d = json.load(sys.stdin)
for n in d['items']:
    print(n['metadata']['name'], 'allocatable.pods=', n['status']['allocatable'].get('pods'))
"
    echo "=== sample FailedScheduling event message ==="
    kubectl -n "$NS" get events --field-selector reason=FailedScheduling -o json 2>/dev/null \
      | python3 -c "
import json,sys
d = json.load(sys.stdin)
for i in d['items']:
    if '$run_id' in i.get('involvedObject',{}).get('name',''):
        print(i.get('message',''))
        break
"
  } > "$rca_path" 2>&1

  python3 -c "
import json
with open('$out_path') as f:
    d = json.load(f)
from collections import Counter
outcomes = Counter(r['outcome'] for r in d['records'])
n_converged = outcomes.get('converged', 0)
ready_times = [r['submit_to_ready_seconds'] for r in d['records'] if r['outcome'] == 'converged']
samples = d['metrics_samples'] or []
rec = {
    'n': $N, 'concurrency': $CONCURRENCY, 'rep': $rep, 'run_id': '$run_id',
    'outcome': 'success', 'git_commit': '$GIT_SHA',
    'convergence_rate': n_converged / d['n'],
    'outcome_breakdown': dict(outcomes),
    'ready_time_mean': (sum(ready_times) / len(ready_times)) if ready_times else None,
    'ready_time_max': max(ready_times) if ready_times else None,
    'ready_time_min': min(ready_times) if ready_times else None,
    'n_metrics_samples': len(samples),
    'operator_cpu_milli_max': max([m['operator_cpu_milli'] for m in samples], default=None),
    'agent_cpu_milli_max': max([m['agent_cpu_milli'] for m in samples], default=None),
    'rca_path': '$rca_path',
}
print(json.dumps(rec))
" >> "$OUT"
  cleanup_scale_run "$run_id"
  sleep 5
done

echo "[e3] done, $(wc -l < "$OUT") lines in $OUT"
