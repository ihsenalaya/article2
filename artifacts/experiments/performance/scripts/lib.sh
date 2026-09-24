#!/usr/bin/env bash
# Shared helpers for Experiment F (Task 09, event-dependent performance
# cost). ON vs OFF is controlled entirely by whether create_on_pod or
# create_off_pod is used -- both create an identical long-running
# perf-workload pod; only ON additionally mints/applies a real signed
# AIPlacementDecision, giving that pod's cgroup an entry in the agent's
# eBPF cgroup_configs map (confirmed by code inspection of
# ebpf-agent/bpf/agent.bpf.c: every tracepoint handler does
# `if (!get_cgroup_config(cgroup_id)) return 0` before any further work --
# an untracked cgroup pays only that lookup+branch, never the full
# path-read/rule-lookup/ring-buffer-submit cost an ON pod's cgroup pays).
# The actual measured workload runs via `kubectl exec` into the
# already-running pod, so ON's decision/policy is fully EnforcementReady
# (and OFF's settle wait has elapsed) before any timed operation starts --
# ruling out a mixed-state measurement window.
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
NS=workloads
EVIDENCE_NS=aiops-system
WORKLOAD_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/perf-workload:task13-mem"

# create_longrunning_pod <pod_name> -- a perf-workload pod that just stays
# alive (ENTRYPOINT is `sleep infinity`); the actual measured operation is
# run on demand via `kubectl exec`. Returns pod UID/node via globals
# POD_UID/NODE_NAME.
create_longrunning_pod() {
  local pod_name="$1"
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  namespace: $NS
  labels: { experiment: performance }
spec:
  restartPolicy: Never
  imagePullSecrets:
    - name: acr-pull-secret
  containers:
    - name: workload
      image: $WORKLOAD_IMAGE
      imagePullPolicy: Always
EOF
  POD_UID="" NODE_NAME=""
  for _ in $(seq 1 60); do
    POD_UID="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    NODE_NAME="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
    [ -n "$POD_UID" ] && [ -n "$NODE_NAME" ] && break
    sleep 0.3
  done
  if [ -z "$POD_UID" ] || [ -z "$NODE_NAME" ]; then
    echo "ERROR: $pod_name did not schedule" >&2
    return 1
  fi
  for _ in $(seq 1 60); do
    local phase
    phase="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [ "$phase" = "Running" ] && return 0
    sleep 0.3
  done
  echo "ERROR: $pod_name never reached Running" >&2
  return 1
}

# mint_and_authorize <pod_name> <decision_version> -- see
# artifacts/experiments/revocation/scripts/lib.sh for the identical,
# already-hardened version of this function (Status.Decision=="active"
# check, not just EnforcementReadyAt -- see that file's comment for the
# replay-collision bug this guards against).
mint_and_authorize() {
  local pod_name="$1" decision_version="$2"
  source "$TRUST_ANCHOR_ENV"
  local decision_yaml
  decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
    --priv-key-hex "$PRIVATE_KEY_HEX" --ttl 6h \
    --name "$pod_name" --namespace "$NS" \
    --target-name "$pod_name" --pod-uid "$POD_UID" --node-identity "$NODE_NAME" \
    --decision-version "$decision_version" 2>/dev/null)"
  echo "$decision_yaml" | kubectl apply -f - >/dev/null
  kubectl -n "$NS" patch aiplacementdecision "$pod_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

  for _ in $(seq 1 120); do
    local ready decision
    ready="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.enforcementReadyAt}' 2>/dev/null || true)"
    decision="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.decision}' 2>/dev/null || true)"
    if [ -n "$ready" ] && [ "$decision" = "active" ]; then
      return 0
    fi
    if [ "$decision" = "rejected" ]; then
      local reason
      reason="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.rejectionReason}' 2>/dev/null || true)"
      echo "ERROR: $pod_name decision rejected (version $decision_version): $reason" >&2
      return 1
    fi
    sleep 0.2
  done
  echo "ERROR: $pod_name policy never became ready+active (version $decision_version)" >&2
  return 1
}

# create_on_pod <pod_name> -- pod + real, EnforcementReady policy (cgroup
# tracked: full eBPF hook path).
create_on_pod() {
  local pod_name="$1"
  create_longrunning_pod "$pod_name" || return 1
  mint_and_authorize "$pod_name" 1 || return 1
}

# create_off_pod <pod_name> <settle_seconds> -- pod only, no decision/
# policy ever created (cgroup untracked: early-return eBPF hook path).
# settle_seconds mirrors the wall-clock delay create_on_pod incurs waiting
# for EnforcementReady, so ON and OFF pods are equally "warmed up" at
# measurement start -- avoids a cold-start confound where OFF always runs
# sooner after pod-Running than ON does.
create_off_pod() {
  local pod_name="$1" settle_seconds="${2:-2}"
  create_longrunning_pod "$pod_name" || return 1
  sleep "$settle_seconds"
}

# run_workload <pod_name> <op> <n> [concurrency] -- execs perf-workload
# inside the already-running pod and returns its single-line JSON result.
# Retries on empty/unparseable output (same defense as
# scale/scripts/lib.sh's run_scale_job, for the same reason: kubectl exec
# output capture can race a container's own readiness under load).
run_workload() {
  local pod_name="$1" op="$2" n="$3" concurrency="${4:-1}"
  local attempt=0
  local out
  while [ "$attempt" -lt 3 ]; do
    out="$(kubectl -n "$NS" exec "$pod_name" -- /perf-workload --op="$op" --n="$n" --concurrency="$concurrency" 2>/dev/null)"
    if [ -n "$out" ] && echo "$out" | tail -n 1 | python3 -c "import json,sys; json.load(sys.stdin)" >/dev/null 2>&1; then
      echo "$out" | tail -n 1
      return 0
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  echo "FAILED"
  return 1
}

# get_evidence_counters <pod_name> -- queries this pod's
# RuntimePlacementEvidence (named after the pod, aiops-system namespace --
# see Task 08's exclusions.md for why it is NOT in $NS) and prints
# dropCount, eventsDroppedSinceLastEvidence, and the sum of Behavior
# counters as a single JSON line. Prints '{}' if no evidence object
# exists yet (e.g., OFF pods never get one).
get_evidence_counters() {
  local pod_name="$1"
  local json
  json="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o json 2>/dev/null)"
  if [ -z "$json" ]; then
    echo "{}"
    return 0
  fi
  echo "$json" | python3 -c "
import json, sys
d = json.load(sys.stdin)
s = d.get('status', {})
b = s.get('behavior', {})
incorporated = sum(b.get(f, 0) for f in ['execAllowed','execDenied','fileOpenAllowed','fileOpenDenied','connectAllowed','connectDenied','deviceAccessAllowed','deviceAccessDenied'])
print(json.dumps({
    'dropCount': s.get('dropCount', 0),
    'eventsDroppedSinceLastEvidence': s.get('eventsDroppedSinceLastEvidence', 0),
    'incorporatedCount': incorporated,
    'conformance': s.get('conformance', 'unset'),
}))
"
}

cleanup_pod() {
  local pod_name="$1"
  kubectl -n "$NS" delete pod "$pod_name" --wait=true --timeout=60s --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS" delete aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
}
