#!/usr/bin/env bash
# Shared helpers for Experiment A (Task 04, admission-to-release closure).
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
LAUNCHER_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/runtime-guard-launcher:cpu-campaign-20260813-task03"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"

# run_trial <run_name> <condition_label> <delay_ms> <out_file>
# Creates one test pod bound to a fresh signed decision, waits for the
# cooperative launcher to release it, records t_p/t_r (from the launcher's
# own JSON) and t_c (from RuntimeSecurityPolicy.Status, agent-observed),
# appends one JSON result line to out_file, then cleans up.
run_trial() {
  local run_name="$1" condition="$2" delay_ms="$3" out_file="$4"
  local ns=workloads
  local start_wall
  start_wall="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

  local delay_annotation=""
  if [ "$delay_ms" -gt 0 ] 2>/dev/null; then
    delay_annotation="    experiment.article2.io/inject-ready-delay-ms: \"$delay_ms\""
  fi

  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: $run_name
  namespace: $ns
  labels: { experiment: closure, condition: "$condition" }
  annotations:
$delay_annotation
spec:
  serviceAccountName: closure-test-runner
  restartPolicy: Never
  imagePullSecrets:
    - name: acr-pull-secret
  initContainers:
    - name: guard-launcher
      image: $LAUNCHER_IMAGE
      args:
        - --policy-name=$run_name
        - --policy-namespace=$ns
        - --timeout=90s
        - --poll-interval=100ms
        - --hold=0s
        - --ready-file=/shared/ready
      volumeMounts: [{name: shared, mountPath: /shared}]
  containers:
    - name: workload
      image: busybox:1.36
      command: ["sh", "-c"]
      args:
        - |
          while [ ! -f /shared/ready ]; do sleep 0.02; done
          wget -T2 -q -O /dev/null http://closure-target-svc.workloads.svc.cluster.local/ || true
          sleep 3600
      volumeMounts: [{name: shared, mountPath: /shared}]
  volumes:
    - name: shared
      emptyDir: {}
EOF
  if [ $? -ne 0 ]; then
    echo "{\"run_id\":\"$run_name\",\"condition\":\"$condition\",\"outcome\":\"failed\",\"reason\":\"pod_apply_failed\"}" >> "$out_file"
    return
  fi

  # Wait for the pod to be scheduled (UID + node known) -- up to 30s.
  local pod_uid="" node_name=""
  for _ in $(seq 1 60); do
    pod_uid="$(kubectl -n "$ns" get pod "$run_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    node_name="$(kubectl -n "$ns" get pod "$run_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
    [ -n "$pod_uid" ] && [ -n "$node_name" ] && break
    sleep 0.5
  done
  if [ -z "$pod_uid" ] || [ -z "$node_name" ]; then
    echo "{\"run_id\":\"$run_name\",\"condition\":\"$condition\",\"outcome\":\"failed\",\"reason\":\"pod_not_scheduled\"}" >> "$out_file"
    kubectl -n "$ns" delete pod "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
    return
  fi

  # Mint and apply the signed decision now that we know the real UID/node.
  source "$TRUST_ANCHOR_ENV"
  local decision_yaml
  decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
    --priv-key-hex "$PRIVATE_KEY_HEX" \
    --name "$run_name" --namespace "$ns" \
    --target-name "$run_name" --pod-uid "$pod_uid" --node-identity "$node_name" 2>/dev/null)"
  if [ -z "$decision_yaml" ]; then
    echo "{\"run_id\":\"$run_name\",\"condition\":\"$condition\",\"outcome\":\"failed\",\"reason\":\"mint_decision_failed\"}" >> "$out_file"
    kubectl -n "$ns" delete pod "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
    return
  fi
  echo "$decision_yaml" | kubectl apply -f - >/dev/null
  kubectl -n "$ns" patch aiplacementdecision "$run_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

  # Wait for the launcher initContainer to terminate (released or timed out).
  local term_reason="" attempt
  for attempt in $(seq 1 200); do
    term_reason="$(kubectl -n "$ns" get pod "$run_name" -o jsonpath='{.status.initContainerStatuses[0].state.terminated.reason}' 2>/dev/null || true)"
    [ -n "$term_reason" ] && break
    sleep 0.5
  done

  local launcher_log launcher_json outcome="success" reason=""
  launcher_log="$(kubectl -n "$ns" logs "$run_name" -c guard-launcher 2>/dev/null || true)"
  launcher_json="$(echo "$launcher_log" | grep -E '^\{' | tail -1)"
  if [ -z "$launcher_json" ]; then
    outcome="failed"
    reason="launcher_did_not_release_${term_reason:-unknown}"
  fi

  # Poll RuntimeSecurityPolicy.Status for t_c (agent-observed), up to 20s.
  local first_obs_ns=""
  if [ "$outcome" = "success" ]; then
    for _ in $(seq 1 40); do
      first_obs_ns="$(kubectl -n "$ns" get runtimesecuritypolicy "$run_name" -o jsonpath='{.status.firstObservedOperationMonotonicNs}' 2>/dev/null || true)"
      [ -n "$first_obs_ns" ] && break
      sleep 0.5
    done
    if [ -z "$first_obs_ns" ]; then
      reason="t_c_not_observed_within_timeout"
    fi
  fi

  local end_wall
  end_wall="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

  LAUNCHER_JSON_LINE="$launcher_json" FIRST_OBS_NS="$first_obs_ns" python3 - "$run_name" "$condition" "$delay_ms" "$outcome" "$reason" "$pod_uid" "$node_name" "$start_wall" "$end_wall" "$GIT_SHA" <<'PYEOF' >> "$out_file"
import json, sys, os
run_name, condition, delay_ms, outcome, reason, pod_uid, node_name, start_wall, end_wall, git_sha = sys.argv[1:11]
launcher_json_line = os.environ.get("LAUNCHER_JSON_LINE", "")
rec = {
    "run_id": run_name, "condition": condition, "delay_ms": int(delay_ms),
    "outcome": outcome, "reason": reason, "pod_uid": pod_uid, "node_name": node_name,
    "start_wall": start_wall, "end_wall": end_wall, "git_commit": git_sha,
}
if launcher_json_line:
    try:
        rec["launcher"] = json.loads(launcher_json_line)
    except Exception as e:
        rec["launcher_parse_error"] = str(e)
first_obs_ns = os.environ.get("FIRST_OBS_NS", "")
rec["first_observed_operation_monotonic_ns"] = int(first_obs_ns) if first_obs_ns else None
if rec.get("launcher") and rec["first_observed_operation_monotonic_ns"] is not None:
    tp = rec["launcher"].get("enforcement_ready_monotonic_ns")
    tr = rec["launcher"].get("gate_released_monotonic_ns")
    tc = rec["first_observed_operation_monotonic_ns"]
    if tp is not None:
        rec["delta_pr_ns"] = tr - tp
    if tr is not None:
        rec["delta_rc_ns"] = tc - tr
print(json.dumps(rec))
PYEOF

  kubectl -n "$ns" delete pod "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
  kubectl -n "$ns" delete aiplacementdecision "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
}
