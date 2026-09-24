#!/usr/bin/env bash
# B1: event loss accounting at increasing offered rates.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/b1-event-loss.jsonl"
: > "$OUT"
IMAGE="acrarticle2ebpftm2ogg.azurecr.io/observation-tools:task05"
DURATION=10

for rate in 100 1000 5000 10000; do
  run_name="b1-rate-${rate}-$RANDOM"
  echo "[b1] rate=${rate}/s duration=${DURATION}s: $run_name"

  # Snapshot node-wide DropCount BEFORE the run (from any currently-tracked
  # evidence object -- DropCount is node-wide, so any recent object works;
  # if none exists yet, treat as 0, which the first real evidence emission
  # after this pod starts will correct).
  drop_before="$(kubectl -n aiops-system get runtimeplacementevidence -o jsonpath='{.items[0].status.dropCount}' 2>/dev/null || echo 0)"
  [ -z "$drop_before" ] && drop_before=0

  if ! create_policy_bound_pod "$run_name" "$IMAGE" "rate-gen" "/etc/hostname" "$rate" "$DURATION"; then
    echo "{\"run_id\":\"$run_name\",\"rate\":$rate,\"outcome\":\"failed\",\"reason\":\"pod_or_policy_setup_failed\"}" >> "$OUT"
    cleanup_pod "$run_name"
    continue
  fi

  # Let generation finish, then wait a FULL evidence-interval (30s) plus
  # margin before reading. The evidence loop uses one global ticker across
  # all tracked pods (ebpf-agent/cmd/agent/main.go evidenceLoop) with
  # CUMULATIVE per-cgroup counters (acc.snapshotAll), so any single tick's
  # snapshot is complete once at least one full tick has elapsed since
  # generation ended -- but breaking on the *first non-empty* read (the
  # original approach) can catch a tick that fired mid-generation or
  # immediately after pod creation, well before the cumulative count is
  # complete, purely depending on random phase alignment with the 30s
  # ticker. That produced non-monotonic, noisy loss rates across rates in
  # the first B1 attempt (61.7/23.65/68.0/34.8%) that were not explained by
  # rate at all. Waiting a fixed, deterministic window >= one full tick
  # removes this confound; we then take a single read rather than
  # early-exiting on the first non-empty value.
  workload_log="$(kubectl -n workloads logs "$run_name" -c workload 2>/dev/null || true)"
  sleep "$((DURATION + 40))"
  workload_log="$(kubectl -n workloads logs "$run_name" -c workload 2>/dev/null || true)"
  attempted="$(echo "$workload_log" | grep -oP 'attempted=\K[0-9]+' | tail -1)"

  behavior_json="$(kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o jsonpath='{.status.behavior}' 2>/dev/null || true)"
  drop_after="$(kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o jsonpath='{.status.dropCount}' 2>/dev/null || true)"

  end_wall="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

  ATTEMPTED="${attempted:-}" BEHAVIOR_JSON="$behavior_json" DROP_BEFORE="$drop_before" DROP_AFTER="${drop_after:-}" \
    python3 - "$run_name" "$rate" "$DURATION" "$GIT_SHA" "$end_wall" <<'PYEOF' >> "$OUT"
import json, sys, os
run_name, rate, duration, git_sha, end_wall = sys.argv[1:6]
attempted = os.environ.get("ATTEMPTED", "")
behavior_raw = os.environ.get("BEHAVIOR_JSON", "{}")
drop_before = os.environ.get("DROP_BEFORE", "0")
drop_after = os.environ.get("DROP_AFTER", "")
try:
    behavior = json.loads(behavior_raw) if behavior_raw else {}
except Exception:
    behavior = {}
observed = sum(int(behavior.get(k, 0)) for k in ("fileOpenAllowed", "fileOpenDenied"))
rec = {
    "run_id": run_name, "rate_per_sec": int(rate), "duration_seconds": int(duration),
    "git_commit": git_sha, "end_wall": end_wall,
    "attempted": int(attempted) if attempted else None,
    "observed_in_evidence": observed,
    "node_drop_count_before": int(drop_before) if drop_before else 0,
    "node_drop_count_after": int(drop_after) if drop_after else None,
}
if rec["attempted"] is not None:
    rec["node_drop_delta"] = (rec["node_drop_count_after"] - rec["node_drop_count_before"]) if rec["node_drop_count_after"] is not None else None
    rec["gap"] = rec["attempted"] - rec["observed_in_evidence"]
    rec["loss_rate"] = rec["gap"] / rec["attempted"] if rec["attempted"] > 0 else None
    rec["outcome"] = "success"
else:
    rec["outcome"] = "failed"
    rec["reason"] = "workload_attempted_count_not_found"
print(json.dumps(rec))
PYEOF

  cleanup_pod "$run_name"
done
echo "[b1] done, $(wc -l < "$OUT") records in $OUT"
