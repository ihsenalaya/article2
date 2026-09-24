#!/usr/bin/env bash
# Measures revocation time: wall-clock delta between deleting an
# AIPlacementDecision (triggering owner-reference garbage collection of its
# RuntimeSecurityPolicy) and the agent's "revoked access" log line for that
# pod. Same patch-first-then-parse-logs-offline methodology as
# measure_propagation.sh, for the same reason (avoids a live-polling race
# against kubectl log latency on this resource-constrained shared VM — see
# that script's header comment for the full story).
#
# Since revocation is destructive (deletes the AIPlacementDecision), this
# script re-mints and re-applies a fresh signed decision before each
# repetition using operator/cmd/mint-test-decision, so the same
# already-running pod can be revoked and re-authorized repeatedly.
#
# Usage: ENV=kind ./measure_revocation.sh <policy-name> <namespace> <pod-uid> <node-identity> <repetitions> <output-csv>
set -uo pipefail

ENVIRONMENT="${ENV:-kind}"
POLICY_NAME="${1:?policy/decision name required}"
NAMESPACE="${2:?namespace required}"
POD_UID="${3:?pod UID required}"
NODE_IDENTITY="${4:?node identity required}"
REPETITIONS="${5:-10}"
OUTPUT_CSV="${6:?output CSV path required}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-runtime-guard-agent-system}"
OPERATOR_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../operator" && pwd)"
RAW_LOG="${OUTPUT_CSV}.agent-logs.txt"

if [ -z "${TRUST_ANCHOR_PRIVATE_KEY_HEX:-}" ]; then
  # shellcheck disable=SC1091
  source "$(dirname "${BASH_SOURCE[0]}")/../../deploy/kind/trust-anchor.env"
  export TRUST_ANCHOR_PRIVATE_KEY_HEX
fi

declare -a T0S=()

# Build once instead of `go run`-ing per repetition: `go run` re-resolves/
# re-links on every call, which at REPETITIONS=30 turned ~14s/rep (per the
# script's own built-in sleeps) into multi-minute gaps and starved the
# controller's reconcile queue when run alongside other campaigns. Built
# under /tmp (an absolute path) defensively, following the same fix applied
# to task14-scalability-policies.py/task14-scalability-pods.py, where a
# relative build-output path got silently re-resolved against operator/
# after that script's build subprocess changed directory.
MINT_BIN="$(mktemp /tmp/measure-revocation-mint-test-decision.XXXXXX)"
(cd "$OPERATOR_DIR" && go build -o "$MINT_BIN" ./cmd/mint-test-decision)
trap 'rm -f "$MINT_BIN"' EXIT

# decision-version must increase on every reauthorization: mint-test-decision
# defaults both --decision-version and --decision-id to constants, so
# without an explicit, incrementing version each subsequent reauthorize()
# presents a fresh nonce at the SAME version -- which the controller's
# anti-replay ledger correctly rejects as "decision replay detected" (same
# version + different nonce is indistinguishable from a forged replay by
# design; see operator/internal/controller/decision_ledger.go). This is
# what was blocking every revocation-timing measurement attempt (both the
# original TASK-14 finding and its H100 reproduction) -- not a controller
# bug. Root-caused 2026-08-10.
DECISION_VERSION=0
reauthorize() {
  DECISION_VERSION=$((DECISION_VERSION + 1))
  "$MINT_BIN" --ttl 6h \
    --name "$POLICY_NAME" --namespace "$NAMESPACE" --target-name "$POLICY_NAME" \
    --pod-uid "$POD_UID" --node-identity "$NODE_IDENTITY" \
    --decision-version "$DECISION_VERSION" \
    | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch aiplacementdecision "$POLICY_NAME" \
    --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null
}

echo "Ensuring $POLICY_NAME is authorized before starting..."
reauthorize
sleep 6 # let the operator generate the RuntimeSecurityPolicy and the agent apply it

for i in $(seq 1 "$REPETITIONS"); do
  T0=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ | sed -E 's/([0-9]{6})[0-9]{3}Z$/\1Z/')
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" delete aiplacementdecision "$POLICY_NAME" >/dev/null 2>&1
  T0S+=("$T0")
  echo "  repetition $i: revoked at t0=$T0"
  sleep 8 # wait for the agent to observe + log the revocation before re-authorizing
  reauthorize
  sleep 6
done

echo "Capturing agent logs..."
# --tail=-1 is required: kubectl logs -l defaults to a 10-line-per-pod tail
# when no --tail is given, which silently truncates the capture to near-
# nothing across multiple agent pods. Same root cause and same fix as
# task12-tetragon-azure-vm.sh's equivalent line -- this file's own version
# of the fix was never actually applied despite being described in a
# comment elsewhere in this file, only caught while re-verifying the E07
# fix on 2026-08-10.
kubectl --context "$KUBE_CONTEXT" -n "$AGENT_NAMESPACE" logs -l app=runtime-guard-agent --since=10m --tail=-1 > "$RAW_LOG" 2>/dev/null

echo "environment,policy_namespace,policy_name,repetition,t0_utc,t1_utc,revocation_seconds" > "$OUTPUT_CSV"
for idx in "${!T0S[@]}"; do
  i=$((idx + 1))
  T0="${T0S[$idx]}"
  # Match the *next* "revoked access" line after T0 for this policy — grep -A
  # style ordering isn't reliable across repetitions, so filter lines after
  # T0 by string comparison (works because timestamps are ISO8601, which
  # sorts lexicographically) and take the first match.
  LINE=$(awk -v t0="$T0" -v pol="policy=$NAMESPACE/$POLICY_NAME" '
    /revoked access/ && index($0, pol) {
      split($1, a, "="); ts = a[2];
      if (ts > t0) { print; exit }
    }' "$RAW_LOG")
  if [ -z "$LINE" ]; then
    echo "$ENVIRONMENT,$NAMESPACE,$POLICY_NAME,$i,$T0,NOTFOUND,NA" >> "$OUTPUT_CSV"
    echo "repetition $i: NOT FOUND in captured log window" >&2
    continue
  fi
  T1=$(echo "$LINE" | grep -oE '^time=[0-9T:.-]+Z' | sed 's/^time=//' | head -1)
  DELTA=$(python3 -c "
import datetime
t0 = datetime.datetime.strptime('$T0', '%Y-%m-%dT%H:%M:%S.%fZ')
t1 = datetime.datetime.strptime('$T1', '%Y-%m-%dT%H:%M:%S.%fZ')
print((t1 - t0).total_seconds())
" 2>/dev/null || echo "NA")
  echo "$ENVIRONMENT,$NAMESPACE,$POLICY_NAME,$i,$T0,$T1,$DELTA" >> "$OUTPUT_CSV"
  echo "repetition $i: revocation=${DELTA}s"
done

echo "Raw results written to $OUTPUT_CSV (agent log window saved to $RAW_LOG)"
