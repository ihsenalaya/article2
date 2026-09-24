#!/usr/bin/env bash
# F1-F3: event-rich workloads (exec/file/network), randomized/counter-
# balanced ON/OFF paired blocks, primary performance metrics (Task 09,
# experiment protocol section 11). Each block creates a fresh ON pod and a
# fresh OFF pod (never reusing pod/decision names across blocks -- see
# revocation/exclusions.md's replay-collision lesson), runs the SAME
# fixed-N operation loop in each, in a RANDOMLY assigned order
# (ON-first or OFF-first) per block, and records both results paired by
# block. Order is randomized, not fixed all-ON-then-all-OFF, per the
# protocol's explicit F2 requirement.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/f1-paired-blocks.jsonl"
: > "$OUT"

# op -> (n_iterations, n_blocks). n_blocks target: >=30 for exec (the
# "important" microbenchmark per F2 -- exec is the primary
# security-relevant hook), reduced for file/network under real time
# constraints on a single live billed cluster (documented scope decision,
# consistent with every prior experiment in this campaign).
declare -A ITERS=( [exec]=2000 [file]=20000 [network]=5000 )
declare -A NBLOCKS=( [exec]=30 [file]=20 [network]=20 )

for op in exec file network; do
  n="${ITERS[$op]}"
  nblocks="${NBLOCKS[$op]}"
  for block in $(seq 1 "$nblocks"); do
    suffix="$RANDOM"
    on_name="f1-${op}-on-b${block}-${suffix}"
    off_name="f1-${op}-off-b${block}-${suffix}"

    # Randomize order: 0 = ON first, 1 = OFF first.
    order=$((RANDOM % 2))
    echo "[f1] op=$op block=$block/$nblocks order=$([ $order -eq 0 ] && echo ON-first || echo OFF-first)"

    on_result="" off_result=""
    if [ "$order" -eq 0 ]; then
      create_on_pod "$on_name" || { echo "[f1]   ON pod setup failed, skipping block" >&2; cleanup_pod "$on_name"; continue; }
      on_result="$(run_workload "$on_name" "$op" "$n")"
      cleanup_pod "$on_name"
      create_off_pod "$off_name" || { echo "[f1]   OFF pod setup failed, skipping block" >&2; cleanup_pod "$off_name"; continue; }
      off_result="$(run_workload "$off_name" "$op" "$n")"
      cleanup_pod "$off_name"
    else
      create_off_pod "$off_name" || { echo "[f1]   OFF pod setup failed, skipping block" >&2; cleanup_pod "$off_name"; continue; }
      off_result="$(run_workload "$off_name" "$op" "$n")"
      cleanup_pod "$off_name"
      create_on_pod "$on_name" || { echo "[f1]   ON pod setup failed, skipping block" >&2; cleanup_pod "$on_name"; continue; }
      on_result="$(run_workload "$on_name" "$op" "$n")"
      cleanup_pod "$on_name"
    fi

    if [ "$on_result" = "FAILED" ] || [ "$off_result" = "FAILED" ]; then
      echo "[f1]   workload exec FAILED (on=$on_result off=$off_result)" >&2
      python3 -c "
import json
print(json.dumps({'op': '$op', 'block': $block, 'order': $order, 'outcome': 'workload_failed', 'git_commit': '$GIT_SHA'}))
" >> "$OUT"
      continue
    fi

    echo "$on_result" > /tmp/f1-on-result.json
    echo "$off_result" > /tmp/f1-off-result.json
    python3 -c "
import json
with open('/tmp/f1-on-result.json') as f: on = json.load(f)
with open('/tmp/f1-off-result.json') as f: off = json.load(f)
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

echo "[f1] done, $(wc -l < "$OUT") records in $OUT"

# --- F3 event count / drop count check (one larger, longer-lived ON run
# per op type, separate from the timing blocks above so the fixed 30s
# evidence-emission tick doesn't inflate every block's wall-clock time). ---
OUT2="$PWD/../raw/f3-event-drop-check.jsonl"
: > "$OUT2"
declare -A BIGN=( [exec]=5000 [file]=50000 [network]=10000 )
for op in exec file network; do
  n="${BIGN[$op]}"
  name="f3-${op}-evidencecheck-$RANDOM"
  echo "[f3] op=$op n=$n run_id=$name"
  create_on_pod "$name" || { echo "[f3]   setup failed" >&2; cleanup_pod "$name"; continue; }
  result="$(run_workload "$name" "$op" "$n")"
  echo "[f3]   waiting 35s for evidence emission tick..."
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
  echo "$result" > /tmp/f3-result.json
  echo "$evidence" > /tmp/f3-evidence.json
  python3 -c "
import json
with open('/tmp/f3-result.json') as f: r = json.load(f)
with open('/tmp/f3-evidence.json') as f: ev = json.load(f)
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

echo "[f3] done, $(wc -l < "$OUT2") records in $OUT2"
