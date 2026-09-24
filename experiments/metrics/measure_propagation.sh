#!/usr/bin/env bash
# Measures policy propagation time: wall-clock delta between issuing a
# RuntimeSecurityPolicy spec change (kubectl patch returning) and the agent's
# "applied policy" log line for that same generation.
#
# Methodology note: an earlier version of this script polled agent logs
# live, inside the same loop that issued each patch, and got spurious
# timeouts even though the target log line demonstably existed (confirmed by
# checking manually seconds later) — a real, reproducible flakiness in doing
# both from the same tight loop on this resource-constrained shared VM, not
# a property of the system being measured. Rather than chase that shell
# scripting issue further, this version separates the two steps: issue every
# patch first (recording T0 for each), wait once at the end for the last
# reconcile to land, then pull the *entire* log window in one shot and match
# generations to timestamps offline. This is more robust regardless of the
# earlier flakiness, since it removes any live race between issuing patches
# and polling for their effect.
#
# Usage: ENV=kind ./measure_propagation.sh <policy-name> <namespace> <repetitions> <output-csv>
set -uo pipefail

ENVIRONMENT="${ENV:-kind}"
POLICY_NAME="${1:?policy name required}"
NAMESPACE="${2:?namespace required}"
REPETITIONS="${3:-10}"
OUTPUT_CSV="${4:?output CSV path required}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-runtime-guard-agent-system}"
RAW_LOG="${OUTPUT_CSV}.agent-logs.txt"

declare -a GENS=()
declare -a T0S=()

echo "Issuing $REPETITIONS patches..."
for i in $(seq 1 "$REPETITIONS"); do
  CURRENT=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$POLICY_NAME" -o jsonpath='{.spec.bpfLock.enabled}')
  if [ "$CURRENT" = "true" ]; then TOGGLE=false; else TOGGLE=true; fi
  # date's %N is nanoseconds (9 digits); Python's strptime %f wants
  # microseconds (6 digits) — truncate, otherwise every parse fails (found
  # empirically: the first version of this fix silently produced NaN/error
  # propagation times for every single repetition).
  T0=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ | sed -E 's/([0-9]{6})[0-9]{3}Z$/\1Z/')
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch runtimesecuritypolicy "$POLICY_NAME" \
    --type=merge -p "{\"spec\":{\"bpfLock\":{\"enabled\":$TOGGLE}}}" >/dev/null
  GENERATION=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$POLICY_NAME" -o jsonpath='{.metadata.generation}')
  GENS+=("$GENERATION")
  T0S+=("$T0")
  echo "  repetition $i: generation=$GENERATION t0=$T0"
  # Space patches clearly beyond the agent's poll interval (5s default) so
  # each generation gets its own poll cycle. Patches issued faster than the
  # poll interval get coalesced — the agent's List() only ever sees the
  # *latest* spec at each tick, so an intermediate generation can be
  # superseded before ever being observed/logged. That's a real, inherent
  # characteristic of poll-based reconciliation, not a bug (see
  # EXPERIMENTS_LOG.md Phase 6) — but it must be avoided here, not measured
  # by accident as if it were a propagation delay.
  sleep 7
done

echo "Waiting for the last reconcile to land..."
sleep 8

echo "Capturing agent logs..."
kubectl --context "$KUBE_CONTEXT" -n "$AGENT_NAMESPACE" logs -l app=runtime-guard-agent --since=5m > "$RAW_LOG" 2>/dev/null

echo "environment,policy_namespace,policy_name,repetition,generation,t0_utc,t1_utc,propagation_seconds" > "$OUTPUT_CSV"
for idx in "${!GENS[@]}"; do
  i=$((idx + 1))
  GENERATION="${GENS[$idx]}"
  T0="${T0S[$idx]}"
  LINE=$(grep "applied policy" "$RAW_LOG" | grep "policy=$NAMESPACE/$POLICY_NAME " | grep "generation=$GENERATION " | tail -1 || true)
  if [ -z "$LINE" ]; then
    echo "$ENVIRONMENT,$NAMESPACE,$POLICY_NAME,$i,$GENERATION,$T0,NOTFOUND,NA" >> "$OUTPUT_CSV"
    echo "repetition $i: NOT FOUND in captured log window (generation $GENERATION)" >&2
    continue
  fi
  # The line is `time=2026-...Z level=INFO msg=...` — the timestamp is
  # prefixed with the literal "time=", not at column 0. An earlier version
  # assumed `^[0-9...]+Z` (no "time=" prefix) and silently extracted an empty
  # string every single time, which is why every prior attempt at this
  # measurement produced parse errors or empty deltas despite the log lines
  # demonstrably being present — a real bug, not the coalescing/timing issue
  # found earlier.
  T1=$(echo "$LINE" | grep -oE '^time=[0-9T:.-]+Z' | sed 's/^time=//' | head -1)
  DELTA=$(python3 -c "
import datetime
t0 = datetime.datetime.strptime('$T0', '%Y-%m-%dT%H:%M:%S.%fZ')
t1 = datetime.datetime.strptime('$T1', '%Y-%m-%dT%H:%M:%S.%fZ')
print((t1 - t0).total_seconds())
")
  echo "$ENVIRONMENT,$NAMESPACE,$POLICY_NAME,$i,$GENERATION,$T0,$T1,$DELTA" >> "$OUTPUT_CSV"
  echo "repetition $i: generation=$GENERATION propagation=${DELTA}s"
done

echo "Raw results written to $OUTPUT_CSV (agent log window saved to $RAW_LOG)"
