#!/usr/bin/env bash
# Task 12 follow-up: re-run G1's deny/allow suite with the new
# COUNTER_LSM_HOOK_ENTERED instrumentation (agent.bpf.c/common.h), to
# resolve Task 10's unexplained finding that DENY conditions never
# blocked despite independently-confirmed-correct kernel policy config.
# Reads event_counters directly from the kernel via bpftool map dump
# (ground truth, not the agent's own reporting path) before and after
# the G1 run, so a delta on index 3 (COUNTER_LSM_HOOK_ENTERED) proves
# whether the kernel invoked the hook at all for the deny attempts.
#
# All output filenames are suffixed with $RUN_NAME (unique per invocation)
# -- an earlier version of this script used fixed filenames and silently
# overwrote 3 of 4 reruns' raw data before it could be archived (see
# ../exclusions.md's "Task 12 follow-up" section). Never repeat that.
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
NS=workloads
RUN_NAME="g1-diag-${1:-run}-$RANDOM"
G1_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/g1-runner:task10-v3"
OUT_DIR="$REPO_ROOT/artifacts/experiments/bpf-lsm/raw"
WORKER_NODE="vm-a2-cpucampaign-20260813-worker"

# bpftool_dump_map <map_name> <out_file> -- kubectl debug node's non-
# interactive attach does not reliably stream command output back through
# shell redirection (`kubectl debug node ... > file` silently produces an
# empty file). The reliable method, confirmed empirically: create the
# debug pod, capture ITS OWN name from stderr, wait for it to complete,
# then `kubectl logs <debug-pod-name>` -- logs are always retrievable
# after the fact regardless of attach behavior.
bpftool_dump_map() {
  local map_name="$1" out_file="$2"
  local create_log
  create_log="$(kubectl debug node/$WORKER_NODE --image=busybox --profile=sysadmin -- \
    chroot /host bpftool map dump name "$map_name" 2>&1 >/dev/null)"
  local debug_pod
  debug_pod="$(echo "$create_log" | grep -oE 'node-debugger-[a-z0-9-]+' | head -1)"
  if [ -z "$debug_pod" ]; then
    echo "WARNING: could not determine debug pod name for $map_name dump" >&2
    echo "{}" > "$out_file"
    return 1
  fi
  for _ in $(seq 1 30); do
    phase="$(kubectl get pod "$debug_pod" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ] && break
    sleep 1
  done
  kubectl logs "$debug_pod" > "$out_file" 2>&1
  kubectl delete pod "$debug_pod" --wait=false --ignore-not-found >/dev/null 2>&1
}

echo "=== creating g1-runner pod $RUN_NAME ==="
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $RUN_NAME
  namespace: $NS
  labels: { experiment: bpf-lsm-followup }
spec:
  restartPolicy: Never
  nodeName: $WORKER_NODE
  imagePullSecrets:
    - name: acr-pull-secret
  containers:
    - name: g1-runner
      image: $G1_IMAGE
      args: ["--bootstrap-wait=25s"]
EOF

echo "=== waiting for pod to be scheduled ==="
pod_uid="" node_name=""
for _ in $(seq 1 60); do
  pod_uid="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  node_name="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
  [ -n "$pod_uid" ] && [ -n "$node_name" ] && break
  sleep 0.5
done
echo "pod_uid=$pod_uid node_name=$node_name"
if [ -z "$pod_uid" ] || [ -z "$node_name" ]; then
  echo "FAILED: pod not scheduled" >&2
  exit 1
fi

echo "=== minting + applying signed decision ==="
source "$TRUST_ANCHOR_ENV"
decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
  --priv-key-hex "$PRIVATE_KEY_HEX" \
  --name "$RUN_NAME" --namespace "$NS" \
  --target-name "$RUN_NAME" --pod-uid "$pod_uid" --node-identity "$node_name" 2>/dev/null)"
if [ -z "$decision_yaml" ]; then
  echo "FAILED: mint-test-decision produced no output" >&2
  exit 1
fi
echo "$decision_yaml" | kubectl apply -f - >/dev/null
kubectl -n "$NS" patch aiplacementdecision "$RUN_NAME" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

echo "=== waiting for operator to derive RuntimeSecurityPolicy/$RUN_NAME ==="
for _ in $(seq 1 60); do
  kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" >/dev/null 2>&1 && break
  sleep 0.5
done
kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o wide

echo "=== patching policy to enforce mode with G1's narrow allow-lists ==="
kubectl -n "$NS" patch runtimesecuritypolicy "$RUN_NAME" --type=merge -p '{
  "spec": {
    "enforcementMode": "enforce",
    "exec": {"defaultAction": "deny", "allowedPaths": ["/bin/true"]},
    "fileAccess": {"defaultAction": "deny", "allowedPathPrefixes": ["/tmp/allowed-testfile"]},
    "networkEgress": {"defaultAction": "deny", "allowedCIDRs": ["127.0.0.1/32"], "allowedPorts": [9999]}
  }
}' >/dev/null
kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o jsonpath='{.spec}' | python3 -m json.tool

echo "=== BEFORE: kernel-ground-truth event_counters (bpftool map dump, host namespace) ==="
bpftool_dump_map event_counters "$OUT_DIR/event_counters_before-$RUN_NAME.json"
cat "$OUT_DIR/event_counters_before-$RUN_NAME.json"

echo "=== waiting for g1-runner to complete (up to 4 minutes: 90s max warmup + test loop) ==="
for _ in $(seq 1 96); do
  phase="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ] && break
  sleep 2.5
done
echo "final pod phase: $phase"

echo "=== AFTER: kernel-ground-truth event_counters ==="
bpftool_dump_map event_counters "$OUT_DIR/event_counters_after-$RUN_NAME.json"
cat "$OUT_DIR/event_counters_after-$RUN_NAME.json"

echo "=== g1-runner's own results (stdout, final JSON line) ==="
kubectl -n "$NS" logs "$RUN_NAME" | tail -1 > "$OUT_DIR/g1-results-$RUN_NAME.json"
kubectl -n "$NS" logs "$RUN_NAME" > "$OUT_DIR/g1-runner-full-log-$RUN_NAME.txt"
cat "$OUT_DIR/g1-results-$RUN_NAME.json" | python3 -m json.tool | head -20

echo "=== cleanup ==="
kubectl -n "$NS" delete pod "$RUN_NAME" --wait=false --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete runtimesecuritypolicy "$RUN_NAME" --wait=false --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete aiplacementdecision "$RUN_NAME" --wait=false --ignore-not-found >/dev/null 2>&1

echo "=== done. Raw outputs in $OUT_DIR/*-$RUN_NAME.* ==="
echo "RUN_NAME=$RUN_NAME"
