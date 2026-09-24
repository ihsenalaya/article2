#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OPERATOR_DIR="$REPO_ROOT/operator"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
NAMESPACE="${TASK05_NAMESPACE:-task05-deterministic}"
TRUST_ANCHOR_ENV="${TRUST_ANCHOR_ENV:-$REPO_ROOT/deploy/kind/trust-anchor.env}"
LEDGER_NAMESPACE="${LEDGER_NAMESPACE:-aiops-system}"
LEDGER_NAME="${LEDGER_NAME:-runtime-guard-decision-ledger}"
RESULTS_CSV="${1:-$REPO_ROOT/results/tasks/TASK-05/raw-data/kind-deterministic-policy-results.csv}"

if [ ! -f "$TRUST_ANCHOR_ENV" ]; then
  echo "missing trust anchor env file: $TRUST_ANCHOR_ENV" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$TRUST_ANCHOR_ENV"
export TRUST_ANCHOR_PRIVATE_KEY_HEX

mkdir -p "$(dirname "$RESULTS_CSV")"
echo "case,expected,actual,result,detail" > "$RESULTS_CSV"

kubectl --context "$KUBE_CONTEXT" delete namespace "$NAMESPACE" --ignore-not-found >/dev/null
kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$LEDGER_NAMESPACE" delete configmap "$LEDGER_NAME" --ignore-not-found >/dev/null

record() {
  local case_name="$1"
  local expected="$2"
  local actual="$3"
  local result="$4"
  local detail="$5"
  echo "$case_name,$expected,$actual,$result,$detail" >> "$RESULTS_CSV"
  echo "$case_name expected=$expected actual=$actual result=$result detail=$detail"
  [ "$result" = "PASS" ]
}

wait_active_policy() {
  local name="$1"
  local decision=""
  for _ in $(seq 1 60); do
    decision="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.decision}' 2>/dev/null || true)"
    if [ "$decision" = "active" ]; then
      return 0
    fi
    sleep 1
  done
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o yaml >&2 || true
  return 1
}

apply_manifest() {
  local manifest="$1"
  local name="$2"
  kubectl --context "$KUBE_CONTEXT" apply -f "$manifest" >/dev/null
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch aiplacementdecision "$name" \
    --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null
  wait_active_policy "$name"
}

mint_manifest() {
  local output="$1"
  local version="$2"
  local nonce="$3"
  local pod_spec_hash="$4"
  local node_identity="$5"
  (cd "$OPERATOR_DIR" && go run ./cmd/mint-test-decision \
    --name deterministic-pod \
    --namespace "$NAMESPACE" \
    --target-name deterministic-pod \
    --pod-uid pod-deterministic-pod \
    --node-identity "$node_identity" \
    --decision-id task05-deterministic-decision \
    --decision-version "$version" \
    --decision-epoch 1 \
    --decision-nonce "$nonce" \
    --pod-spec-hash "$pod_spec_hash") > "$output"
}

policy_jsonpath() {
  local path="$1"
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy deterministic-pod -o jsonpath="$path"
}

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

first_manifest="$tmpdir/decision-v1.yaml"
second_manifest="$tmpdir/decision-v2.yaml"
mint_manifest "$first_manifest" 1 nonce-task05-v1 specHash-task05-v1 article2-worker
apply_manifest "$first_manifest" deterministic-pod

first_policy_hash="$(policy_jsonpath '{.spec.derivation.policyHash}')"
first_decision_hash="$(policy_jsonpath '{.spec.derivation.decisionHash}')"
first_token_hash="$(policy_jsonpath '{.spec.derivation.tokenHash}')"
first_evidence_hash="$(policy_jsonpath '{.spec.derivation.evidenceHash}')"
first_ref="$(policy_jsonpath '{.spec.placementDecisionRef.namespace}/{.spec.placementDecisionRef.name}')"
first_decision_id="$(policy_jsonpath '{.spec.binding.decisionID}')"

if [ -n "$first_policy_hash" ] && [ -n "$first_decision_hash" ] && [ -n "$first_token_hash" ] && [ -n "$first_evidence_hash" ]; then
  record trace-present nonempty nonempty PASS "D/P/T/token hashes recorded"
else
  record trace-present nonempty missing FAIL "policy=$first_policy_hash decision=$first_decision_hash token=$first_token_hash evidence=$first_evidence_hash"
fi

if [ "$first_ref" = "$NAMESPACE/deterministic-pod" ] && [ "$first_decision_id" = "task05-deterministic-decision" ]; then
  record origin-linked "$NAMESPACE/deterministic-pod" "$first_ref" PASS "decisionID=$first_decision_id"
else
  record origin-linked "$NAMESPACE/deterministic-pod" "$first_ref" FAIL "decisionID=$first_decision_id"
fi

kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" annotate aiplacementdecision deterministic-pod task05-reconcile="$(date -u +%s%N)" --overwrite >/dev/null
wait_active_policy deterministic-pod
second_same_policy_hash="$(policy_jsonpath '{.spec.derivation.policyHash}')"
second_same_decision_hash="$(policy_jsonpath '{.spec.derivation.decisionHash}')"

if [ "$first_policy_hash" = "$second_same_policy_hash" ] && [ "$first_decision_hash" = "$second_same_decision_hash" ]; then
  record same-D-equivalent-P unchanged unchanged PASS "policyHash=$second_same_policy_hash"
else
  record same-D-equivalent-P unchanged changed FAIL "policyHash=$first_policy_hash->$second_same_policy_hash decisionHash=$first_decision_hash->$second_same_decision_hash"
fi

mint_manifest "$second_manifest" 2 nonce-task05-v2 specHash-task05-v2 article2-control-plane
apply_manifest "$second_manifest" deterministic-pod

altered_policy_hash="$(policy_jsonpath '{.spec.derivation.policyHash}')"
altered_decision_hash="$(policy_jsonpath '{.spec.derivation.decisionHash}')"
altered_pod_spec_hash="$(policy_jsonpath '{.spec.binding.podSpecHash}')"
altered_node_identity="$(policy_jsonpath '{.spec.binding.nodeIdentity}')"

if [ "$first_policy_hash" != "$altered_policy_hash" ] && [ "$first_decision_hash" != "$altered_decision_hash" ]; then
  record altered-D-changes-P changed changed PASS "policyHash=$first_policy_hash->$altered_policy_hash"
else
  record altered-D-changes-P changed unchanged FAIL "policyHash=$first_policy_hash->$altered_policy_hash decisionHash=$first_decision_hash->$altered_decision_hash"
fi

if [ "$altered_pod_spec_hash" = "specHash-task05-v2" ] && [ "$altered_node_identity" = "article2-control-plane" ]; then
  record stale-P-not-reused updated updated PASS "podSpecHash=$altered_pod_spec_hash nodeIdentity=$altered_node_identity"
else
  record stale-P-not-reused updated stale FAIL "podSpecHash=$altered_pod_spec_hash nodeIdentity=$altered_node_identity"
fi

echo "results written to $RESULTS_CSV"
