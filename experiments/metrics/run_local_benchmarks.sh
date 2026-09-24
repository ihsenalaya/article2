#!/usr/bin/env bash
# TASK-11 local performance/statistical harness.
#
# One command builds the local CLIs, creates deterministic verifier fixtures,
# repeats local-only benchmarks, writes raw CSV, and derives statistics. These
# measurements are deliberately CPU/local CLI timings; they do not claim or
# infer H100 performance.
#
# Usage:
#   experiments/metrics/run_local_benchmarks.sh --repetitions 10 --output-dir results/tasks/TASK-11
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPETITIONS="${REPETITIONS:-5}"
OUT_DIR="${TASK11_OUT_DIR:-$REPO_ROOT/results/tasks/TASK-11}"

usage() {
  cat <<'EOF'
usage: run_local_benchmarks.sh [--repetitions N] [--output-dir DIR]

Environment:
  REPETITIONS       default repetition count when --repetitions is omitted
  TASK11_OUT_DIR    default output directory when --output-dir is omitted
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repetitions)
      REPETITIONS="${2:?missing value for --repetitions}"
      shift 2
      ;;
    --output-dir)
      OUT_DIR="${2:?missing value for --output-dir}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if ! [[ "$REPETITIONS" =~ ^[1-9][0-9]*$ ]]; then
  echo "repetitions must be a positive integer, got: $REPETITIONS" >&2
  exit 2
fi

if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$REPO_ROOT/$OUT_DIR"
fi

RAW_DIR="$OUT_DIR/raw-data"
PROCESSED_DIR="$OUT_DIR/processed"
STDOUT_DIR="$OUT_DIR/stdout"
STDERR_DIR="$OUT_DIR/stderr"
FIXTURE_DIR="$OUT_DIR/fixtures/evidence"
RAW_CSV="$RAW_DIR/local-benchmark-raw.csv"
STATS_CSV="$PROCESSED_DIR/local-benchmark-stats.csv"
STATS_MD="$PROCESSED_DIR/local-benchmark-stats.md"

mkdir -p "$RAW_DIR" "$PROCESSED_DIR" "$STDOUT_DIR" "$STDERR_DIR" "$FIXTURE_DIR"

BUILD_DIR="$(mktemp -d "${TMPDIR:-/tmp}/task11-local-bench.XXXXXX")"
cleanup() {
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

VERIFY_BIN="$BUILD_DIR/verify-evidence"
LAUNCHER_BIN="$BUILD_DIR/runtime-guard-launcher"
READY_FILE="$BUILD_DIR/runtime-guard-ready"
MISSING_READY_FILE="$BUILD_DIR/runtime-guard-missing"

echo "task=TASK-11 local_benchmark repetitions=$REPETITIONS out_dir=$OUT_DIR"
echo "note=local_cpu_cli_timings_no_h100_inference"

echo "building local benchmark binaries..."
(cd "$REPO_ROOT/operator" && go build -o "$VERIFY_BIN" ./cmd/verify-evidence)
(cd "$REPO_ROOT/operator" && go build -o "$LAUNCHER_BIN" ./cmd/runtime-guard-launcher)

echo "creating deterministic evidence fixture..."
TASK08_OUT_DIR="$FIXTURE_DIR" "$REPO_ROOT/experiments/attacks/task08-evidence-verifier.sh" \
  > "$STDOUT_DIR/evidence-fixture.out" \
  2> "$STDERR_DIR/evidence-fixture.err"

PUBLIC_KEY_HEX="$(cat "$FIXTURE_DIR/raw-data/agent-public-key.hex")"
POLICY_FILE="$FIXTURE_DIR/yaml/policy.yaml"
EVIDENCE_FILE="$FIXTURE_DIR/yaml/evidence.yaml"

echo "benchmark,iteration,started_at_utc,elapsed_ms,exit_code,expected_exit_code,outcome,detail" > "$RAW_CSV"

perf_counter_ns() {
  python3 - <<'PY'
import time
print(time.perf_counter_ns())
PY
}

elapsed_ms() {
  local start_ns="$1"
  local end_ns="$2"
  python3 - "$start_ns" "$end_ns" <<'PY'
import sys
start_ns = int(sys.argv[1])
end_ns = int(sys.argv[2])
print(f"{(end_ns - start_ns) / 1_000_000:.3f}")
PY
}

record_measurement() {
  local benchmark_name="$1"
  local repetition_number="$2"
  local expected_exit_code="$3"
  local detail="$4"
  shift 4

  local started_at_utc
  started_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local start_ns
  start_ns="$(perf_counter_ns)"

  set +e
  "$@" > "$STDOUT_DIR/${benchmark_name}-${repetition_number}.out" \
    2> "$STDERR_DIR/${benchmark_name}-${repetition_number}.err"
  local exit_code=$?
  set -e

  local end_ns
  end_ns="$(perf_counter_ns)"
  local elapsed
  elapsed="$(elapsed_ms "$start_ns" "$end_ns")"
  local outcome="fail"
  if [[ "$exit_code" -eq "$expected_exit_code" ]]; then
    outcome="pass"
  fi

  echo "$benchmark_name,$repetition_number,$started_at_utc,$elapsed,$exit_code,$expected_exit_code,$outcome,$detail" >> "$RAW_CSV"
  echo "benchmark=$benchmark_name repetition=$repetition_number elapsed_ms=$elapsed exit=$exit_code expected=$expected_exit_code outcome=$outcome"
}

echo "ready" > "$READY_FILE"
rm -f "$MISSING_READY_FILE"

for repetition_number in $(seq 1 "$REPETITIONS"); do
  record_measurement verify_evidence_valid "$repetition_number" 0 valid_evidence \
    "$VERIFY_BIN" \
      --evidence-file "$EVIDENCE_FILE" \
      --policy-file "$POLICY_FILE" \
      --public-key-hex "$PUBLIC_KEY_HEX" \
      --now-unix 1030 \
      --max-age 1m

  record_measurement verify_evidence_stale_reject "$repetition_number" 1 expected_freshness_reject \
    "$VERIFY_BIN" \
      --evidence-file "$EVIDENCE_FILE" \
      --policy-file "$POLICY_FILE" \
      --public-key-hex "$PUBLIC_KEY_HEX" \
      --now-unix 1200 \
      --max-age 1m

  record_measurement launcher_probe_ready "$repetition_number" 0 ready_file_present \
    "$LAUNCHER_BIN" --probe-ready --ready-file "$READY_FILE"

  record_measurement launcher_probe_not_ready "$repetition_number" 1 ready_file_absent \
    "$LAUNCHER_BIN" --probe-ready --ready-file "$MISSING_READY_FILE"
done

python3 "$REPO_ROOT/experiments/metrics/analyze_local_benchmarks.py" "$RAW_CSV" "$STATS_CSV" "$STATS_MD"

echo "raw_csv=$RAW_CSV"
echo "stats_csv=$STATS_CSV"
echo "stats_md=$STATS_MD"
