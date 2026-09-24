#!/usr/bin/env bash
# B3: silence vs monitor-dead. Creates a normal policy-bound workload,
# captures a baseline evidence LastHeartbeat, then kills the agent pod on
# that node and checks whether the resulting STALE evidence is correctly
# flagged as monitor-dead by verify-evidence's monitor-heartbeat-fresh
# check, and that a subsequently-recovered monitor is correctly NOT
# flagged (Q5).
#
# Two prior attempts at this test were invalidated by timing bugs, both
# left here as lessons rather than silently fixed away:
#   1. Waiting the full outage window (45s) before checking at all: the
#      DaemonSet self-heals fast enough (~30-45s) that by the time of the
#      check, a fresh heartbeat had already been emitted -- the test never
#      actually observed a "monitor genuinely dead" state.
#   2. Using --max-age 20s, shorter than the 30s production evidence-tick
#      interval: a perfectly healthy monitor's heartbeat naturally ranges
#      0-30s old between ticks (sawtooth), so a 20s threshold produces
#      false "stale" flags on a live monitor roughly (30-20)/30 of the
#      time purely from tick-phase timing, independent of any real outage
#      -- this is exactly what happened on a "post-recovery" check that
#      should have read FRESH.
#
# This version fixes both: max-age is set comfortably above the tick
# interval (45s = 1.5x), and the DaemonSet is prevented from recreating
# the killed pod (via a temporary nodeSelector no node satisfies -- the
# DaemonSet tolerates all taints, so tainting the node does not work) for
# long enough to deterministically exceed max-age while genuinely still
# dead, confirmed directly via kubectl rather than assumed from a sleep
# duration.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/b3-monitor-liveness.jsonl"
: > "$OUT"
IMAGE="busybox:1.36"
run_name="b3-liveness-$RANDOM"
DS_NS=runtime-guard-agent-system
DS_NAME=runtime-guard-agent
MAX_AGE_SECONDS=45
MAX_AGE="${MAX_AGE_SECONDS}s"

echo "[b3] creating policy-bound workload: $run_name"
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $run_name
  namespace: workloads
  labels: { experiment: observation-completeness }
spec:
  restartPolicy: Never
  containers:
    - name: workload
      image: $IMAGE
      command: ["sh", "-c"]
      args:
        - |
          while true; do cat /etc/hostname >/dev/null 2>&1; sleep 1; done
EOF

pod_uid="" node_name=""
for _ in $(seq 1 60); do
  pod_uid="$(kubectl -n workloads get pod "$run_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  node_name="$(kubectl -n workloads get pod "$run_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
  [ -n "$pod_uid" ] && [ -n "$node_name" ] && break
  sleep 0.3
done
echo "[b3] scheduled on node: $node_name"

source "$TRUST_ANCHOR_ENV"
decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
  --priv-key-hex "$PRIVATE_KEY_HEX" \
  --name "$run_name" --namespace workloads \
  --target-name "$run_name" --pod-uid "$pod_uid" --node-identity "$node_name" 2>/dev/null)"
echo "$decision_yaml" | kubectl apply -f - >/dev/null
kubectl -n workloads patch aiplacementdecision "$run_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

echo "[b3] waiting for first evidence with a live heartbeat..."
baseline_heartbeat=""
for _ in $(seq 1 60); do
  baseline_heartbeat="$(kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o jsonpath='{.status.lastHeartbeat}' 2>/dev/null || true)"
  [ -n "$baseline_heartbeat" ] && break
  sleep 1
done
echo "[b3] baseline lastHeartbeat: $baseline_heartbeat"

agent_pub_key_hex="$(grep PUBLIC_KEY_HEX "$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/agent-signing.env" | cut -d= -f2)"

# check_heartbeat <label> -- captures the current evidence object and runs
# verify-evidence against it with --max-age $MAX_AGE. Prints
# "<lastHeartbeat>|<monitor-heartbeat-fresh-passed(true/false/unknown)>".
# Captures verify-evidence's stdout ONLY (2>/dev/null): a prior version
# captured 2>&1, which on a failing check mixes `go run`'s own "exit
# status 1" stderr diagnostic into the JSON text, breaking json.load and
# silently producing "unknown" for every failing check.
check_heartbeat() {
  local label="$1"
  local tmpdir heartbeat report failed
  tmpdir="$(mktemp -d)"
  kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o yaml > "$tmpdir/evidence.yaml"
  kubectl -n workloads get runtimesecuritypolicy "$run_name" -o yaml > "$tmpdir/policy.yaml"
  heartbeat="$(kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o jsonpath='{.status.lastHeartbeat}' 2>/dev/null || true)"
  report="$(cd "$REPO_ROOT/operator" && go run ./cmd/verify-evidence \
    --evidence-file "$tmpdir/evidence.yaml" --policy-file "$tmpdir/policy.yaml" \
    --public-key-hex "$agent_pub_key_hex" \
    --max-age "$MAX_AGE" 2>/dev/null)"
  cp "$tmpdir/evidence.yaml" "$PWD/../verifier-output/b3-${label}-evidence.yaml"
  echo "$report" > "$PWD/../verifier-output/b3-${label}-verify-report.json"
  failed="$(echo "$report" | python3 -c "
import json,sys
try:
    r = json.load(sys.stdin)
    for c in r.get('checks', []):
        if c['name'] == 'monitor-heartbeat-fresh':
            print('true' if not c['passed'] else 'false')
            sys.exit(0)
except Exception:
    pass
print('unknown')
")"
  rm -rf "$tmpdir"
  echo "${heartbeat}|${failed}"
}

echo "[b3] blocking DaemonSet recreation via temporary nodeSelector (DaemonSet tolerates all taints, so tainting the node does not work)..."
kubectl -n "$DS_NS" patch daemonset "$DS_NAME" --type=merge -p '{"spec":{"template":{"spec":{"nodeSelector":{"b3-block-recreate":"true"}}}}}' >/dev/null

agent_pod="$(kubectl -n "$DS_NS" get pods -o jsonpath="{.items[?(@.spec.nodeName=='$node_name')].metadata.name}" 2>/dev/null)"
echo "[b3] killing agent pod on $node_name: $agent_pod (blocked from recreating -- recoverable, see unblock step below)"
kubectl -n "$DS_NS" delete pod "$agent_pod" --wait=false >/dev/null 2>&1

dead_wait=$((MAX_AGE_SECONDS + 15))
echo "[b3] agent down and recreation blocked; waiting ${dead_wait}s (max-age=${MAX_AGE_SECONDS}s + 15s margin) before the dead-monitor check..."
sleep "$dead_wait"

no_new_pod="$(kubectl -n "$DS_NS" get pods -o jsonpath="{.items[?(@.spec.nodeName=='$node_name')].metadata.name}" 2>/dev/null || true)"
echo "[b3] agent pods on $node_name during blocked window: '${no_new_pod:-<none>}' (expected empty)"

dead_result="$(check_heartbeat dead-monitor)"
dead_heartbeat="${dead_result%%|*}"
dead_flagged="${dead_result##*|}"
echo "[b3] dead-monitor check: heartbeat=$dead_heartbeat flagged_stale=$dead_flagged"

echo "[b3] unblocking DaemonSet recreation..."
kubectl -n "$DS_NS" patch daemonset "$DS_NAME" --type=json -p '[{"op":"remove","path":"/spec/template/spec/nodeSelector"}]' >/dev/null
kubectl -n "$DS_NS" rollout status daemonset/"$DS_NAME" --timeout=120s >/dev/null 2>&1 || true
new_agent_pod="$(kubectl -n "$DS_NS" get pods -o jsonpath="{.items[?(@.spec.nodeName=='$node_name')].metadata.name}" 2>/dev/null)"
echo "[b3] recovered agent pod: $new_agent_pod"

recovery_wait=$((MAX_AGE_SECONDS - 5))
echo "[b3] waiting ${recovery_wait}s past self-heal for a fresh evidence tick (kept under max-age so a live monitor is NOT flagged)..."
sleep "$recovery_wait"
recovered_result="$(check_heartbeat recovered-monitor)"
recovered_heartbeat="${recovered_result%%|*}"
recovered_flagged="${recovered_result##*|}"
echo "[b3] recovered-monitor check: heartbeat=$recovered_heartbeat flagged_stale=$recovered_flagged"

behavior_final="$(kubectl -n aiops-system get runtimeplacementevidence "$run_name" -o jsonpath='{.status.behavior}' 2>/dev/null || true)"

python3 -c "
import json
print(json.dumps({
    'run_id': '$run_name',
    'node_name': '$node_name',
    'max_age_seconds': $MAX_AGE_SECONDS,
    'evidence_tick_interval_seconds': 30,
    'baseline_heartbeat': '$baseline_heartbeat',
    'dead_wait_seconds': $dead_wait,
    'confirmed_no_new_agent_pod_during_block': '$no_new_pod' == '',
    'dead_monitor_heartbeat': '$dead_heartbeat',
    'dead_monitor_heartbeat_unchanged_from_baseline': '$dead_heartbeat' == '$baseline_heartbeat',
    'dead_monitor_verify_evidence_flagged_stale': '$dead_flagged',
    'agent_self_healed_after_unblock': '$new_agent_pod' != '',
    'recovery_wait_seconds': $recovery_wait,
    'recovered_monitor_heartbeat': '$recovered_heartbeat',
    'recovered_monitor_heartbeat_advanced': '$recovered_heartbeat' != '$dead_heartbeat',
    'recovered_monitor_verify_evidence_flagged_stale': '$recovered_flagged',
    'behavior_final': json.loads('''$behavior_final''') if '''$behavior_final''' else {},
    'git_commit': '$GIT_SHA',
}))
" >> "$OUT"

cleanup_pod "$run_name"
echo "[b3] done, $(wc -l < "$OUT") records in $OUT"
