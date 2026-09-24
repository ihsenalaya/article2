#!/usr/bin/env bash
# Task 12 follow-up: re-run F3's event/drop-count check using the FIXED
# perf-workload image (exec's Stdin/Stdout/Stderr now explicitly inherited
# instead of left nil -- see operator/cmd/perf-workload/main.go's comment
# and artifacts/experiments/performance/exclusions.md), to confirm the
# original ~19x incorporated_count anomaly on the exec op was caused by
# Go's os/exec opening /dev/null per nil stream, not by RuntimeGuard's own
# event-counting logic. Writes to a SEPARATE output file -- the original
# f3-event-drop-check.jsonl (task06 commit, unfixed binary) is retained
# unmodified per experiment protocol rule 21.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

WORKLOAD_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/perf-workload:task12-fixed"

OUT2="$PWD/../raw/f3-event-drop-check-task12-fixed.jsonl"
: > "$OUT2"
declare -A BIGN=( [exec]=5000 [file]=50000 [network]=10000 )
for op in exec file network; do
  n="${BIGN[$op]}"
  name="f3fix-${op}-evidencecheck-$RANDOM"
  echo "[f3-fixed] op=$op n=$n run_id=$name"
  create_on_pod "$name" || { echo "[f3-fixed]   setup failed" >&2; cleanup_pod "$name"; continue; }
  result="$(run_workload "$name" "$op" "$n")"
  echo "[f3-fixed]   waiting 35s for evidence emission tick..."
  sleep 35
  evidence="$(get_evidence_counters "$name")"
  cleanup_pod "$name"
  if [ "$result" = "FAILED" ]; then
    python3 -c "
import json
print(json.dumps({'op': '$op', 'n': $n, 'outcome': 'workload_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT2"
    continue
  fi
  echo "$result" > /tmp/f3fix-result.json
  echo "$evidence" > /tmp/f3fix-evidence.json
  python3 -c "
import json
with open('/tmp/f3fix-result.json') as f: r = json.load(f)
with open('/tmp/f3fix-evidence.json') as f: ev = json.load(f)
rec = {
    'op': '$op', 'n': $n, 'outcome': 'success', 'git_commit': '$GIT_SHA',
    'n_completed': r['n_completed'], 'cpu_total_seconds': r['cpu_total_seconds'],
    'drop_count': ev.get('dropCount'),
    'events_dropped_since_last_evidence': ev.get('eventsDroppedSinceLastEvidence'),
    'incorporated_count': ev.get('incorporatedCount'),
    'conformance': ev.get('conformance'),
}
print(json.dumps(rec))
" >> "$OUT2"
done

echo "[f3-fixed] done, $(wc -l < "$OUT2") records in $OUT2"
cat "$OUT2"
