#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OPERATOR_DIR="$REPO_ROOT/operator"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
NAMESPACE="${TASK06_NAMESPACE:-task06-temporal-closure}"
TRUST_ANCHOR_ENV="${TRUST_ANCHOR_ENV:-$REPO_ROOT/deploy/kind/trust-anchor.env}"
LEDGER_NAMESPACE="${LEDGER_NAMESPACE:-aiops-system}"
LEDGER_NAME="${LEDGER_NAME:-runtime-guard-decision-ledger}"
RESULTS_CSV="${1:-$REPO_ROOT/results/tasks/TASK-06/raw-data/kind-temporal-closure-results.csv}"
LAUNCHER_IMAGE="${LAUNCHER_IMAGE:-runtime-guard-launcher:dev}"
# Real Azure VM nodes are not named "article2-worker" -- allow overriding the
# node this pod is pinned to (via nodeSelector) so this script works against
# a real VM cluster, not just kind. Defaults preserve exact prior kind behavior.
NODE_NAME="${NODE_NAME:-article2-worker}"
# kind load docker-image only makes sense when actually targeting kind --
# skip it against a real cluster (the image is preloaded into VM containerd
# separately) to avoid wasting time loading into an unrelated local cluster.
SKIP_KIND_LOAD="${SKIP_KIND_LOAD:-0}"

if [ ! -f "$TRUST_ANCHOR_ENV" ]; then
  echo "missing trust anchor env file: $TRUST_ANCHOR_ENV" >&2
  exit 1
fi

# shellcheck disable=SC1090
source "$TRUST_ANCHOR_ENV"
export TRUST_ANCHOR_PRIVATE_KEY_HEX

mkdir -p "$(dirname "$RESULTS_CSV")"
echo "case,expected,actual,result,detail" > "$RESULTS_CSV"

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

wait_policy_active() {
  local name="$1"
  for _ in $(seq 1 90); do
    local decision
    decision="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.decision}' 2>/dev/null || true)"
    if [ "$decision" = "active" ]; then
      return 0
    fi
    sleep 1
  done
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o yaml >&2 || true
  return 1
}

wait_policy_enforcement_ready() {
  local name="$1"
  for _ in $(seq 1 90); do
    local generation applied condition ready_at
    generation="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
    applied="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.appliedPolicyGeneration}' 2>/dev/null || true)"
    condition="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.conditions[?(@.type=="EnforcementReady")].status}' 2>/dev/null || true)"
    ready_at="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o jsonpath='{.status.enforcementReadyAt}' 2>/dev/null || true)"
    if [ -n "$generation" ] && [ "$generation" = "$applied" ] && [ "$condition" = "True" ] && [ -n "$ready_at" ]; then
      return 0
    fi
    sleep 1
  done
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get runtimesecuritypolicy "$name" -o yaml >&2 || true
  return 1
}

json_value() {
  local json="$1"
  local key="$2"
  python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2], ""))' "$json" "$key"
}

time_le() {
  local left="$1"
  local right="$2"
  python3 -c 'from datetime import datetime, timezone; import sys

def parse(s):
    s=s.replace("Z","+00:00")
    if "." in s:
        head, tail = s.split(".", 1)
        frac, zone = tail, ""
        for marker in ("+", "-"):
            if marker in tail:
                frac, zone = tail.split(marker, 1)
                zone = marker + zone
                break
        s = head + "." + frac[:6].ljust(6, "0") + zone
    return datetime.fromisoformat(s).astimezone(timezone.utc)
sys.exit(0 if parse(sys.argv[1]) <= parse(sys.argv[2]) else 1)' "$left" "$right"
}

kubectl --context "$KUBE_CONTEXT" delete namespace "$NAMESPACE" --ignore-not-found >/dev/null
kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$LEDGER_NAMESPACE" delete configmap "$LEDGER_NAME" --ignore-not-found >/dev/null

if [ "$SKIP_KIND_LOAD" != "1" ]; then
  docker build -f "$REPO_ROOT/experiments/runtime-guard-launcher/Dockerfile" -t "$LAUNCHER_IMAGE" "$REPO_ROOT" >/dev/null
  kind load docker-image "$LAUNCHER_IMAGE" --name article2 >/dev/null
fi

cat <<YAML | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
apiVersion: v1
kind: ServiceAccount
metadata:
  name: runtime-guard-launcher
  namespace: $NAMESPACE
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: runtime-guard-launcher
  namespace: $NAMESPACE
rules:
  - apiGroups: ["aiops.imperium.io"]
    resources: ["runtimesecuritypolicies"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: runtime-guard-launcher
  namespace: $NAMESPACE
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: runtime-guard-launcher
subjects:
  - kind: ServiceAccount
    name: runtime-guard-launcher
    namespace: $NAMESPACE
YAML

(cd "$OPERATOR_DIR" && go run ./cmd/mint-test-decision \
  --name guarded-workload \
  --namespace "$NAMESPACE" \
  --target-name guarded-workload \
  --pod-uid pod-guarded-workload \
  --node-identity "$NODE_NAME" \
  --decision-id task06-guarded-workload \
  --decision-version 1 \
  --decision-epoch 1 \
  --decision-nonce nonce-task06-guarded) | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" patch aiplacementdecision guarded-workload \
  --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null
wait_policy_active guarded-workload

cat <<YAML | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: guarded-workload
  namespace: $NAMESPACE
  labels:
    app: guarded-workload
spec:
  serviceAccountName: runtime-guard-launcher
  nodeSelector:
    kubernetes.io/hostname: $NODE_NAME
  restartPolicy: Never
  containers:
    - name: guarded
      image: $LAUNCHER_IMAGE
      imagePullPolicy: IfNotPresent
      env:
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
      args:
        - --policy-name=guarded-workload
        - --policy-namespace=$NAMESPACE
        - --timeout=120s
        - --poll-interval=250ms
        - --hold=30s
        - --ready-file=/tmp/runtime-guard-ready
      readinessProbe:
        exec:
          command:
            - /runtime-guard-launcher
            - --probe-ready
            - --ready-file=/tmp/runtime-guard-ready
        periodSeconds: 1
        failureThreshold: 1
YAML

wait_policy_enforcement_ready guarded-workload
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" wait --for=condition=Ready pod/guarded-workload --timeout=90s >/dev/null

release_json=""
for _ in $(seq 1 90); do
  release_json="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" logs pod/guarded-workload -c guarded 2>/dev/null | tail -n 1 || true)"
  if echo "$release_json" | grep -q 'critical_operation_at'; then
    break
  fi
  sleep 1
done
if ! echo "$release_json" | grep -q 'critical_operation_at'; then
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" describe pod guarded-workload >&2 || true
  kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" logs pod/guarded-workload -c guarded >&2 || true
  record guarded-release-log present missing FAIL "launcher did not emit release JSON"
fi

enforcement_ready_at="$(json_value "$release_json" enforcement_ready_at)"
gate_released_at="$(json_value "$release_json" gate_released_at)"
critical_operation_at="$(json_value "$release_json" critical_operation_at)"
applied_generation="$(json_value "$release_json" applied_policy_generation)"
policy_generation="$(json_value "$release_json" policy_generation)"
applied_cgroups="$(json_value "$release_json" applied_cgroup_ids)"
pod_ready_at="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod guarded-workload -o jsonpath='{.status.conditions[?(@.type=="Ready")].lastTransitionTime}')"

gate_start_order="FAIL"
if time_le "$enforcement_ready_at" "$gate_released_at" && time_le "$gate_released_at" "$critical_operation_at"; then
  gate_start_order="PASS"
fi
record guarded-order "ready<=release<=critical" "$enforcement_ready_at<=$gate_released_at<=$critical_operation_at" "$gate_start_order" "generation=$applied_generation/$policy_generation cgroups=$applied_cgroups"

pod_ready_order="FAIL"
if time_le "$enforcement_ready_at" "$pod_ready_at"; then
  pod_ready_order="PASS"
fi
record pod-ready-after-enforcement "enforcementReady<=podReady" "$enforcement_ready_at<=$pod_ready_at" "$pod_ready_order" "readinessProbe tied to ready-file"

if [ "$applied_generation" = "$policy_generation" ] && [ -n "$applied_generation" ]; then
  record current-generation-ready current current PASS "generation=$applied_generation"
else
  record current-generation-ready current stale FAIL "generation=$applied_generation/$policy_generation"
fi

cat <<YAML | kubectl --context "$KUBE_CONTEXT" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: unguarded-race
  namespace: $NAMESPACE
spec:
  restartPolicy: Never
  containers:
    - name: unguarded
      image: $LAUNCHER_IMAGE
      imagePullPolicy: IfNotPresent
      args:
        - --policy-name=missing-policy
        - --policy-namespace=$NAMESPACE
        - --timeout=1s
        - --poll-interval=250ms
        - --hold=1s
YAML

sleep 3
unguarded_logs="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" logs pod/unguarded-race -c unguarded 2>/dev/null || true)"
unguarded_phase="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod unguarded-race -o jsonpath='{.status.phase}' 2>/dev/null || true)"
if echo "$unguarded_logs" | grep -q 'critical_operation_at'; then
  record unguarded-race-blocked blocked released FAIL "launcher released critical operation without a policy"
else
  record unguarded-race-blocked blocked blocked PASS "phase=$unguarded_phase no critical_operation_at without policy"
fi

echo "results written to $RESULTS_CSV"
