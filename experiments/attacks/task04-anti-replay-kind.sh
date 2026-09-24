#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OPERATOR_DIR="$REPO_ROOT/operator"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
NAMESPACE="${TASK04_NAMESPACE:-task04-anti-replay}"
TRUST_ANCHOR_ENV="${TRUST_ANCHOR_ENV:-$REPO_ROOT/deploy/kind/trust-anchor.env}"
LEDGER_NAMESPACE="${LEDGER_NAMESPACE:-aiops-system}"
LEDGER_NAME="${LEDGER_NAME:-runtime-guard-decision-ledger}"
RESULTS_CSV="${1:-$REPO_ROOT/results/tasks/TASK-04/raw-data/kind-anti-replay-results.csv}"

if [ ! -f "$TRUST_ANCHOR_ENV" ]; then
  echo "missing trust anchor env file: $TRUST_ANCHOR_ENV" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$TRUST_ANCHOR_ENV"
export TRUST_ANCHOR_PRIVATE_KEY_HEX

mkdir -p "$(dirname "$RESULTS_CSV")"
echo "case,expected,actual,reason,result" > "$RESULTS_CSV"

kubectl --context "$KUBE_CONTEXT" delete namespace "$NAMESPACE" --ignore-not-found >/dev/null
kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$LEDGER_NAMESPACE" delete configmap "$LEDGER_NAME" --ignore-not-found >/dev/null

wait_policy_status() {
  local name="$1"
  local expected="$2"
  local actual=""
  local reason=""
  for _ in $(seq 1 60); do
    actual="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.decision}' 2>/dev/null || true)"
    reason="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.rejectionReason}' 2>/dev/null || true)"
    if [ "$actual" = "$expected" ]; then
      printf '%s|%s\n' "$actual" "$reason"
      return 0
    fi
    sleep 1
  done
  printf '%s|%s\n' "$actual" "$reason"
  return 1
}

apply_decision() {
  local name="$1"
  local decision_id="$2"
  local version="$3"
  local nonce="$4"
  local expected="$5"
  shift 5

  (cd "$OPERATOR_DIR" && go run ./cmd/mint-test-decision \
    --name "$name" \
    --namespace "$NAMESPACE" \
    --target-name "$name" \
    --pod-uid "pod-$name" \
    --node-identity "article2-worker" \
    --decision-id "$decision_id" \
    --decision-version "$version" \
    --decision-epoch 1 \
    --decision-nonce "$nonce" \
    "$@") | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null

  local status_decision="allow"
  for arg in "$@"; do
    case "$arg" in
      --status-decision=*) status_decision="${arg#--status-decision=}" ;;
    esac
  done
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch aiplacementdecision "$name" \
    --subresource=status --type=merge -p "{\"status\":{\"decision\":\"$status_decision\"}}" >/dev/null

  local observed
  local result="PASS"
  if ! observed="$(wait_policy_status "$name" "$expected")"; then
    result="FAIL"
  fi
  local actual="${observed%%|*}"
  local reason="${observed#*|}"
  # reason is free text and can contain a literal comma (e.g. an ed25519
  # length-mismatch message), which breaks field alignment for any
  # downstream consumer using a standards-compliant CSV parser unless it's
  # quoted here -- quote it and double any embedded double-quotes per RFC 4180.
  local reason_escaped="${reason//\"/\"\"}"
  printf '%s,%s,%s,"%s",%s\n' "$name" "$expected" "$actual" "$reason_escaped" "$result" >> "$RESULTS_CSV"
  echo "$name expected=$expected actual=$actual result=$result reason=$reason"
  [ "$result" = "PASS" ]
}

apply_decision valid-current task04-valid-current 1 nonce-valid active
apply_decision modified-payload task04-modified 1 nonce-modified rejected --tamper-node-identity-after-signing=attacker-node
apply_decision invalid-signature task04-invalid-signature 1 nonce-invalid-signature rejected --signature-override=00
apply_decision wrong-key task04-wrong-key 1 nonce-wrong-key rejected --priv-key-hex=0000000000000000000000000000000000000000000000000000000000000000
apply_decision expired task04-expired 1 nonce-expired rejected --ttl=-1m

apply_decision replay-source-a task04-replay-shared 1 nonce-replay active
apply_decision replay-source-b task04-replay-shared 1 nonce-replay rejected

apply_decision older-version-current task04-older-version 2 nonce-older-v2 active
apply_decision older-version-replay task04-older-version 1 nonce-older-v1 rejected

apply_decision rollback task04-rollback 2 nonce-rollback-v2 active
apply_decision rollback task04-rollback 1 nonce-rollback-v1 rejected

apply_decision revoked task04-revoked 1 nonce-revoked rejected --status-decision=revoked

echo "results written to $RESULTS_CSV"
