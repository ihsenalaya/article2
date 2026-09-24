#!/usr/bin/env bash
# B2: Omega-class coverage matrix / alternate-path bypass testing.
# For each pair (alternate-path syscall, control syscall), run both against
# a policy-bound pod and compare RuntimePlacementEvidence.Behavior deltas.
# Audit-mode tracepoints only attach to sys_enter_{execve,open,openat}
# (ebpf-agent/internal/loader/loader.go attachAudit) -- execveat and
# openat2 are NOT hooked in audit mode, so this is expected, from static
# analysis, to show a real observation gap; this experiment verifies that
# expectation empirically rather than asserting it.
#
# The pod wrapper itself (GATE_START's wait loop, plus the shell forking to
# exec the probe binary) generates its own baseline file-open/exec activity
# that the audit hooks legitimately observe -- a pilot run showed
# execDenied=2 even for the openat2 case, which makes zero exec calls,
# proving this baseline is real and non-negligible relative to a single
# probe syscall. A raw non-zero counter therefore cannot distinguish "the
# probed syscall was observed" from "the wrapper's own overhead was
# observed". altpath-probe's default case (an unrecognized mode) does zero
# file/exec syscalls before exiting, so it isolates pure wrapper overhead;
# we run that first as a baseline and attribute only the counter DELTA
# above baseline to the probed syscall.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/b2-altpath-coverage.jsonl"
: > "$OUT"
IMAGE="acrarticle2ebpftm2ogg.azurecr.io/observation-tools:task05"

echo "[b2] measuring wrapper-only baseline (noop probe mode)..."
baseline_name="b2-baseline-$RANDOM"
baseline_json="{}"
if create_policy_bound_pod "$baseline_name" "$IMAGE" "altpath-probe" "noop" "/etc/hostname"; then
  # Fixed wait >= one full evidence tick (30s) + margin, then a single read
  # -- not "poll until first non-empty", which can catch a partial
  # mid-tick snapshot depending on random phase alignment (the same bug
  # fixed in B1's run-b1.sh after it produced non-monotonic loss rates).
  sleep 40
  baseline_json="$(kubectl -n aiops-system get runtimeplacementevidence "$baseline_name" -o jsonpath='{.status.behavior}' 2>/dev/null || true)"
  [ -z "$baseline_json" ] && baseline_json="{}"
fi
echo "[b2] baseline counters: $baseline_json"
cleanup_pod "$baseline_name"
export BASELINE_JSON="$baseline_json"

run_probe() {
  local case_name="$1" probe_mode="$2" target="$3"
  local run_name="b2-${case_name}-$RANDOM"
  echo "[b2] $case_name ($probe_mode $target): $run_name"

  if ! create_policy_bound_pod "$run_name" "$IMAGE" "altpath-probe" "$probe_mode" "$target"; then
    echo "{\"run_id\":\"$run_name\",\"case\":\"$case_name\",\"probe_mode\":\"$probe_mode\",\"outcome\":\"failed\",\"reason\":\"setup_failed\"}" >> "$OUT"
    cleanup_pod "$run_name"
    return
  fi

  sleep 3
  local probe_log
  probe_log="$(kubectl -n workloads logs "$run_name" -c workload 2>&1 || true)"
  local probe_ok="false"
  echo "$probe_log" | grep -qi "succeeded\|failed to replace process" && probe_ok="true"

  # Same fixed-wait-then-single-read discipline as the baseline above.
  sleep 40
  behavior_json="$(kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o jsonpath='{.status.behavior}' 2>/dev/null || true)"

  PROBE_LOG="$probe_log" BEHAVIOR_JSON="$behavior_json" PROBE_OK="$probe_ok" python3 - "$run_name" "$case_name" "$probe_mode" "$target" "$GIT_SHA" <<'PYEOF' >> "$OUT"
import json, sys, os
run_name, case_name, probe_mode, target, git_sha = sys.argv[1:6]
behavior_raw = os.environ.get("BEHAVIOR_JSON", "{}")
baseline_raw = os.environ.get("BASELINE_JSON", "{}")
try:
    behavior = json.loads(behavior_raw) if behavior_raw else {}
except Exception:
    behavior = {}
try:
    baseline = json.loads(baseline_raw) if baseline_raw else {}
except Exception:
    baseline = {}
observed = sum(int(v) for v in behavior.values()) if behavior else 0
baseline_total = sum(int(v) for v in baseline.values()) if baseline else 0
delta = observed - baseline_total
delta_by_key = {k: int(behavior.get(k, 0)) - int(baseline.get(k, 0)) for k in set(behavior) | set(baseline)}
rec = {
    "run_id": run_name, "case": case_name, "probe_mode": probe_mode, "target": target,
    "git_commit": git_sha, "outcome": "success",
    "probe_syscall_succeeded": os.environ.get("PROBE_OK") == "true",
    "probe_log": os.environ.get("PROBE_LOG", "")[:500],
    "behavior_counters": behavior,
    "baseline_counters": baseline,
    "total_observed_events": observed,
    "baseline_total_events": baseline_total,
    "delta_over_baseline": delta,
    "delta_by_key": delta_by_key,
    "observed_by_ebpf": delta > 0,
}
print(json.dumps(rec))
PYEOF

  cleanup_pod "$run_name"
}

TARGET_FILE=/etc/hostname
TARGET_BIN=/bin/true

# Control paths (already-hooked syscalls) -- expect observed_by_ebpf=true.
run_probe "control-openat" "openat" "$TARGET_FILE"
run_probe "control-execve" "execve" "$TARGET_BIN"

# Alternate paths (NOT hooked by audit-mode tracepoints per static analysis)
# -- expect observed_by_ebpf=false, demonstrating the real bypass.
run_probe "altpath-openat2" "openat2" "$TARGET_FILE"
run_probe "altpath-execveat" "execveat" "$TARGET_BIN"

echo "[b2] done, $(wc -l < "$OUT") records in $OUT"
