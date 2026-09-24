#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${TASK09_OUT_DIR:-$REPO_ROOT/results/tasks/TASK-09}"
if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$REPO_ROOT/$OUT_DIR"
fi
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
NAMESPACE="${TASK09_NAMESPACE:-task09-fail-closed}"
LAUNCHER_IMAGE="${LAUNCHER_IMAGE:-runtime-guard-launcher:task09}"
CSV="$OUT_DIR/raw-data/fail-closed-results.csv"
# kind load docker-image only makes sense when actually targeting kind --
# skip it against a real cluster (image preloaded into VM containerd
# separately).
SKIP_KIND_LOAD="${SKIP_KIND_LOAD:-0}"

mkdir -p "$OUT_DIR/raw-data" "$OUT_DIR/stdout" "$OUT_DIR/stderr" "$OUT_DIR/yaml"
echo "mode,injection,expected_observation,actual_observation,classification,result,evidence" > "$CSV"

record() {
  local mode="$1"
  local injection="$2"
  local expected="$3"
  local actual="$4"
  local classification="$5"
  local result="$6"
  local evidence="$7"
  printf '%s,%s,%s,%s,%s,%s,%s\n' "$mode" "$injection" "$expected" "$actual" "$classification" "$result" "$evidence" >> "$CSV"
  echo "$mode classification=$classification result=$result actual=$actual"
  [[ "$result" = "PASS" ]]
}

run_expect_exit() {
  local name="$1"
  local expected_code="$2"
  shift 2
  set +e
  "$@" > "$OUT_DIR/stdout/$name.out" 2> "$OUT_DIR/stderr/$name.err"
  local code=$?
  set -e
  echo "$code" > "$OUT_DIR/raw-data/$name.exit-code"
  [[ "$code" = "$expected_code" ]]
}

VALID_SEED="0707070707070707070707070707070707070707070707070707070707070707"
VALID_DIGEST="repo/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

if run_expect_exit agent-missing-signing-key 1 \
  bash -lc "cd '$REPO_ROOT/ebpf-agent' && go run ./cmd/agent --node-name=node-1 --agent-image-digest='$VALID_DIGEST' --signing-key-hex=" &&
  grep -q "signing-key-hex is required" "$OUT_DIR/stdout/agent-missing-signing-key.out"; then
  record agent-missing-signing-key omit-signing-key "process exits before monitor starts" "exit=1 signing-key required" fail-closed PASS "stdout/agent-missing-signing-key.out"
else
  record agent-missing-signing-key omit-signing-key "process exits before monitor starts" "unexpected" unresolved FAIL "stdout/agent-missing-signing-key.out"
fi

if run_expect_exit agent-missing-image-digest 1 \
  bash -lc "cd '$REPO_ROOT/ebpf-agent' && go run ./cmd/agent --node-name=node-1 --agent-image-digest= --signing-key-hex='$VALID_SEED'" &&
  grep -q "agent-image-digest is required" "$OUT_DIR/stdout/agent-missing-image-digest.out"; then
  record agent-missing-image-digest omit-agent-image-digest "process exits before monitor starts" "exit=1 image digest required" fail-closed PASS "stdout/agent-missing-image-digest.out"
else
  record agent-missing-image-digest omit-agent-image-digest "process exits before monitor starts" "unexpected" unresolved FAIL "stdout/agent-missing-image-digest.out"
fi

if run_expect_exit launcher-stale-generation 0 \
  bash -lc "cd '$REPO_ROOT/operator' && go test -count=1 ./cmd/runtime-guard-launcher -run TestIsCurrentEnforcementReadyRejectsStaleGeneration -v"; then
  record launcher-stale-generation stale-applied-policy-generation "release gate rejects stale generation" "unit test passed" fail-closed PASS "stdout/launcher-stale-generation.out"
else
  record launcher-stale-generation stale-applied-policy-generation "release gate rejects stale generation" "unit test failed" unresolved FAIL "stdout/launcher-stale-generation.out"
fi

if run_expect_exit evidence-corrupt-binding 0 \
  bash -lc "cd '$REPO_ROOT/operator' && go test -count=1 ./cmd/verify-evidence -run TestVerifyEvidenceRejectsTamperedDecisionBinding -v"; then
  record evidence-corrupt-binding tamper-decision-hash "external verifier rejects tampering" "unit test passed" fail-closed PASS "stdout/evidence-corrupt-binding.out"
else
  record evidence-corrupt-binding tamper-decision-hash "external verifier rejects tampering" "unit test failed" unresolved FAIL "stdout/evidence-corrupt-binding.out"
fi

if run_expect_exit lsm-state-missing 0 \
  bash -lc "cd '$REPO_ROOT/ebpf-agent' && go test -count=1 ./internal/lsmdetect -run TestDetermineMode_AuditWhenFileMissing -v"; then
  record lsm-state-missing missing-securityfs-lsm-file "agent falls back to audit mode" "unit test passed; mode=audit" unresolved PASS "stdout/lsm-state-missing.out"
else
  record lsm-state-missing missing-securityfs-lsm-file "agent falls back to audit mode" "unit test failed" unresolved FAIL "stdout/lsm-state-missing.out"
fi

if run_expect_exit evidence-stale 0 \
  bash -lc "TASK08_OUT_DIR='$OUT_DIR' '$REPO_ROOT/experiments/attacks/task08-evidence-verifier.sh'" &&
  [[ "$(cat "$OUT_DIR/raw-data/verify-evidence-stale-exit-code.txt")" = "1" ]]; then
  record evidence-stale verifier-now-exceeds-max-age "external verifier exits 1 for stale evidence" "stale_exit=1" fail-closed PASS "raw-data/verify-evidence-stale-report.json"
else
  record evidence-stale verifier-now-exceeds-max-age "external verifier exits 1 for stale evidence" "unexpected" unresolved FAIL "raw-data/verify-evidence-stale-report.json"
fi

kubectl --context "$KUBE_CONTEXT" delete namespace "$NAMESPACE" --ignore-not-found >/dev/null
kubectl --context "$KUBE_CONTEXT" create namespace "$NAMESPACE" >/dev/null
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-operator-system delete deployment runtime-guard-operator-controller-manager --ignore-not-found > "$OUT_DIR/stdout/controller-kill.out" 2> "$OUT_DIR/stderr/controller-kill.err" || true

if [ "$SKIP_KIND_LOAD" != "1" ]; then
  docker build -f "$REPO_ROOT/experiments/runtime-guard-launcher/Dockerfile" -t "$LAUNCHER_IMAGE" "$REPO_ROOT" > "$OUT_DIR/stdout/launcher-image-build.out" 2> "$OUT_DIR/stderr/launcher-image-build.err"
  kind load docker-image "$LAUNCHER_IMAGE" --name article2 > "$OUT_DIR/stdout/launcher-image-load.out" 2> "$OUT_DIR/stderr/launcher-image-load.err"
fi

cat > "$OUT_DIR/yaml/missing-policy-gate.yaml" <<YAML
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
---
apiVersion: v1
kind: Pod
metadata:
  name: missing-policy-gate
  namespace: $NAMESPACE
spec:
  serviceAccountName: runtime-guard-launcher
  restartPolicy: Never
  containers:
    - name: guarded
      image: $LAUNCHER_IMAGE
      imagePullPolicy: IfNotPresent
      args:
        - --policy-name=policy-never-created
        - --policy-namespace=$NAMESPACE
        - --timeout=2s
        - --poll-interval=250ms
        - --hold=1s
YAML

kubectl --context "$KUBE_CONTEXT" apply -f "$OUT_DIR/yaml/missing-policy-gate.yaml" > "$OUT_DIR/stdout/missing-policy-apply.out" 2> "$OUT_DIR/stderr/missing-policy-apply.err"
for _ in $(seq 1 60); do
  phase="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod missing-policy-gate -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  if [[ "$phase" = "Failed" || "$phase" = "Succeeded" ]]; then
    break
  fi
  sleep 1
done
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod missing-policy-gate -o yaml > "$OUT_DIR/yaml/missing-policy-pod.yaml" 2> "$OUT_DIR/stderr/missing-policy-pod.err" || true
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" logs pod/missing-policy-gate -c guarded > "$OUT_DIR/stdout/missing-policy-gate.out" 2> "$OUT_DIR/stderr/missing-policy-gate.err" || true
phase="$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod missing-policy-gate -o jsonpath='{.status.phase}' 2>/dev/null || true)"
if ! grep -q "critical_operation_at" "$OUT_DIR/stdout/missing-policy-gate.out" && [[ "$phase" = "Failed" || "$phase" = "Succeeded" ]]; then
  record controller-outage-missing-policy delete-controller-and-never-create-policy "guarded workload must not release critical operation" "phase=$phase no critical_operation_at" fail-closed PASS "stdout/missing-policy-gate.out"
else
  record controller-outage-missing-policy delete-controller-and-never-create-policy "guarded workload must not release critical operation" "phase=$phase released-or-unknown" fail-open FAIL "stdout/missing-policy-gate.out"
fi

kubectl --context "$KUBE_CONTEXT" delete namespace "$NAMESPACE" --ignore-not-found > "$OUT_DIR/stdout/cleanup-namespace.out" 2> "$OUT_DIR/stderr/cleanup-namespace.err" || true
echo "results written to $CSV"
