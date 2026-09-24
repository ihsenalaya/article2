#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${TASK10_OUT_DIR:-$REPO_ROOT/results/tasks/TASK-10}"
if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$REPO_ROOT/$OUT_DIR"
fi
SUMMARY="$OUT_DIR/raw-data/kind-attack-campaign-summary.csv"

mkdir -p "$OUT_DIR/raw-data" "$OUT_DIR/stdout" "$OUT_DIR/stderr" "$OUT_DIR/subruns"
echo "case,command,exit_code,result,raw_artifact" > "$SUMMARY"

run_case() {
  local case_name="$1"
  local command="$2"
  local raw_artifact="$3"
  local stdout_path="$OUT_DIR/stdout/${case_name}.out"
  local stderr_path="$OUT_DIR/stderr/${case_name}.err"
  set +e
  (cd "$REPO_ROOT" && bash -lc "$command") > "$stdout_path" 2> "$stderr_path"
  local code=$?
  set -e
  local result="PASS"
  if [[ "$code" -ne 0 ]]; then
    result="FAIL"
  fi
  printf '%s,"%s",%s,%s,%s\n' "$case_name" "$command" "$code" "$result" "$raw_artifact" >> "$SUMMARY"
  echo "$case_name exit_code=$code result=$result raw_artifact=$raw_artifact"
  [[ "$code" -eq 0 ]]
}

run_case task04-anti-replay \
  "TASK04_NAMESPACE=task10-anti-replay experiments/attacks/task04-anti-replay-kind.sh '$OUT_DIR/raw-data/task04-anti-replay.csv'" \
  "raw-data/task04-anti-replay.csv"

run_case task05-deterministic-policy \
  "TASK05_NAMESPACE=task10-deterministic experiments/attacks/task05-deterministic-policy-kind.sh '$OUT_DIR/raw-data/task05-deterministic-policy.csv'" \
  "raw-data/task05-deterministic-policy.csv"

run_case task06-temporal-closure \
  "TASK06_NAMESPACE=task10-temporal-closure LAUNCHER_IMAGE=runtime-guard-launcher:task10 experiments/attacks/task06-temporal-closure-kind.sh '$OUT_DIR/raw-data/task06-temporal-closure.csv'" \
  "raw-data/task06-temporal-closure.csv"

run_case task07-mediation-coverage \
  "cd ebpf-agent && go test -count=1 ./internal/mediation ./internal/policy" \
  "stdout/task07-mediation-coverage.out"

run_case task08-evidence-verifier \
  "TASK08_OUT_DIR='$OUT_DIR/subruns/task08-evidence-verifier' experiments/attacks/task08-evidence-verifier.sh" \
  "subruns/task08-evidence-verifier/raw-data/verify-evidence-valid-report.json"

run_case task09-fail-closed \
  "TASK09_OUT_DIR='$OUT_DIR/subruns/task09-fail-closed' TASK09_NAMESPACE=task10-fail-closed LAUNCHER_IMAGE=runtime-guard-launcher:task10-failclosed experiments/attacks/task09-fail-closed-kind.sh" \
  "subruns/task09-fail-closed/raw-data/fail-closed-results.csv"

run_case final-kind-restore \
  "deploy/kind/create-lab.sh" \
  "stdout/final-kind-restore.out"

echo "summary written to $SUMMARY"
