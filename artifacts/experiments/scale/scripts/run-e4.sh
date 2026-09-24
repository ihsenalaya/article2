#!/usr/bin/env bash
# E4: event integrity under scale (Task 08, experiment protocol section 10,
# mandatory). N=100 concurrent decisions, n=3 reps. After each run
# converges/times out, pods/policies/evidence are deliberately left alive
# for >1 evidence-emission tick (30s, see environment.json) before
# querying every RuntimePlacementEvidence created by the run, THEN
# cleaning up -- so this measures the real evidence pipeline under the
# same load E1 exercised, not a synthetic afterthought.
#
# Measurement mapping (see summary.md for the full justification):
#   kernel drop count        -> Status.DropCount (cumulative) and
#                                Status.EventsDroppedSinceLastEvidence
#                                (delta this window), both read directly
#                                from the agent's eBPF event_counters map
#                                (ebpf-agent/internal/loader/loader.go).
#   event generation rate    -> not independently instrumented (no
#                                kernel Generated counter is exposed via
#                                the CRD, and adding one is a change this
#                                task does not require -- see below).
#   user-space received count
#   evidence incorporated count
#                                -> both equal sum(Status.Behavior.*) across
#                                every evidence object the run produced.
#                                In this implementation these are the SAME
#                                measured quantity: accumulator.handle()
#                                (ebpf-agent/cmd/agent/main.go) increments
#                                Behavior counters directly off the ring
#                                buffer read, with no separate
#                                received-but-not-yet-incorporated stage.
#                                This is reported as an architectural
#                                finding, not assumed.
#
# agent.bpf.c/common.h establish Generated == Emitted + Dropped by
# construction (loader.go's EventCounters doc comment). So DropCount
# (kernel-measured) staying 0 across a run is sufficient, by that
# invariant, to establish Generated == Emitted for that run without a
# separately exposed Generated readout -- which is why no such readout
# was added here.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/e4-event-integrity.jsonl"
: > "$OUT"

N=100
CONCURRENCY=100
CONVERGE_TIMEOUT="300s"
POST_CONVERGE_WAIT=40

for rep in 1 2 3; do
  run_id="e4-rep${rep}-$RANDOM"
  echo "[e4] rep=$rep run_id=$run_id"
  out_path="$(run_scale_job "$N" "$CONCURRENCY" "$run_id" "$CONVERGE_TIMEOUT")"
  if [ "$out_path" = "FAILED" ] || [ ! -f "$out_path" ]; then
    echo "[e4]   FAILED (job-level)" >&2
    python3 -c "
import json
print(json.dumps({'n': $N, 'rep': $rep, 'run_id': '$run_id', 'outcome': 'job_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
    cleanup_scale_run "$run_id"
    continue
  fi

  echo "[e4]   waiting ${POST_CONVERGE_WAIT}s for evidence emission ticks..."
  sleep "$POST_CONVERGE_WAIT"

  evidence_path="$PWD/../raw/${run_id}.evidence.json"
  # Evidence objects live in the agent's --evidence-namespace, "aiops-system"
  # by default -- NOT the workload namespace ($NS) the pods/decisions live
  # in. Querying $NS here was a real bug in this script's first run (0
  # evidence objects found for 100/100 converged pods across all 3 reps),
  # not a RuntimeGuard finding -- see exclusions.md.
  kubectl -n aiops-system get runtimeplacementevidence -o json > "$evidence_path" 2>/dev/null

  python3 -c "
import json
with open('$out_path') as f:
    gen = json.load(f)
with open('$evidence_path') as f:
    ev = json.load(f)

prefix = 'scale-$run_id-'
items = [i for i in ev['items'] if i['metadata']['name'].startswith(prefix)]

n_converged = sum(1 for r in gen['records'] if r['outcome'] == 'converged')
n_evidence = len(items)

drop_counts = [i['status'].get('dropCount', 0) for i in items]
events_dropped_deltas = [i['status'].get('eventsDroppedSinceLastEvidence', 0) for i in items]
conformance = {}
for i in items:
    c = i['status'].get('conformance', 'unset')
    conformance[c] = conformance.get(c, 0) + 1

behavior_fields = ['execAllowed','execDenied','fileOpenAllowed','fileOpenDenied',
                    'connectAllowed','connectDenied','deviceAccessAllowed','deviceAccessDenied']
behavior_sum = {f: sum(i['status'].get('behavior', {}).get(f, 0) for i in items) for f in behavior_fields}
total_incorporated = sum(behavior_sum.values())

rec = {
    'n': $N, 'concurrency': $CONCURRENCY, 'rep': $rep, 'run_id': '$run_id',
    'outcome': 'success', 'git_commit': '$GIT_SHA',
    'n_converged': n_converged,
    'n_evidence_objects': n_evidence,
    'evidence_coverage': (n_evidence / $N) if $N else None,
    'drop_count_max': max(drop_counts) if drop_counts else None,
    'events_dropped_since_last_evidence_sum': sum(events_dropped_deltas) if events_dropped_deltas else None,
    'events_dropped_since_last_evidence_nonzero_count': sum(1 for d in events_dropped_deltas if d),
    'conformance_breakdown': conformance,
    'behavior_sum': behavior_sum,
    'user_space_received_and_incorporated_count': total_incorporated,
}
print(json.dumps(rec))
" >> "$OUT"
  cleanup_scale_run "$run_id"
  sleep 3
done

echo "[e4] done, $(wc -l < "$OUT") lines in $OUT"
