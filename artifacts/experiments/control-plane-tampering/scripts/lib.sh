#!/usr/bin/env bash
# Shared helpers for Experiment: control-plane tampering (Task 11).
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
NS=workloads
MINT_BIN="/tmp/mint-test-decision"
AGENT_POD="runtime-guard-agent-2m6xb"
AGENT_NS="runtime-guard-agent-system"

# create_and_authorize <pod_name> -- creates a busybox pod on the worker
# node, mints and applies a real signed AIPlacementDecision for it, waits
# for the pod UID/node.
create_and_authorize() {
  local pod_name="$1"
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  namespace: $NS
  labels: { experiment: control-plane-tampering }
spec:
  restartPolicy: Never
  nodeName: vm-a2-cpucampaign-20260813-worker
  imagePullSecrets:
    - name: acr-pull-secret
  containers:
    - name: workload
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF
  local pod_uid=""
  for _ in $(seq 1 30); do
    pod_uid="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    [ -n "$pod_uid" ] && break
    sleep 0.3
  done
  if [ -z "$pod_uid" ]; then
    echo "ERROR: $pod_name did not schedule" >&2
    return 1
  fi
  POD_UID="$pod_uid"

  source "$TRUST_ANCHOR_ENV"
  local decision_yaml
  decision_yaml="$("$MINT_BIN" --priv-key-hex "$PRIVATE_KEY_HEX" --ttl 6h \
    --name "$pod_name" --namespace "$NS" \
    --target-name "$pod_name" --pod-uid "$POD_UID" --node-identity vm-a2-cpucampaign-20260813-worker \
    --decision-version 1 2>/dev/null)"
  echo "$decision_yaml" | kubectl apply -f - >/dev/null
  kubectl -n "$NS" patch aiplacementdecision "$pod_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

  for _ in $(seq 1 60); do
    local ready
    ready="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.enforcementReadyAt}' 2>/dev/null || true)"
    [ -n "$ready" ] && return 0
    sleep 0.3
  done
  echo "ERROR: $pod_name policy never became ready" >&2
  return 1
}

# steady_state_verdict <pod_name> -- waits past the initial poll cycle's
# possible AIPlacementDecision-status-propagation race (observed
# empirically: the FIRST reconcile after minting can catch
# status.decision still empty, correctly rejecting transiently -- not a
# bug, see summary.md), then reports the verdict from the two MOST RECENT
# reconcile-cycle log lines for this policy, requiring them to agree
# (stable steady state, not a snapshot mid-transition).

# Note: "applied policy" only logs on a Generation CHANGE (see main.go),
# so a stably-accepted, unchanged policy logs it exactly ONCE and then
# goes silent -- unlike "validation FAILED", which logs every reconcile
# cycle a policy fails. steady_state_verdict therefore takes the single
# MOST RECENT relevant line, and if it reads REJECTED, re-checks after
# one more poll interval to rule out the transient status-propagation
# race observed early in this experiment (see summary.md) before
# reporting a final verdict.
_latest_verdict() {
  local pod_name="$1"
  local line
  line="$(kubectl -n "$AGENT_NS" logs "$AGENT_POD" 2>/dev/null | grep "policy=$NS/$pod_name " | tail -1)"
  if [ -z "$line" ]; then
    echo "NO_DATA"
    return
  fi
  if echo "$line" | grep -q "validation FAILED"; then
    echo "REJECTED:$(echo "$line" | sed -n 's/.*reason="\(.*\)"$/\1/p')"
  else
    echo "ACCEPTED"
  fi
}

steady_state_verdict() {
  local pod_name="$1"
  sleep 9
  local v1
  v1="$(_latest_verdict "$pod_name")"
  case "$v1" in
    REJECTED:*)
      sleep 6
      _latest_verdict "$pod_name"
      ;;
    *)
      echo "$v1"
      ;;
  esac
}

cleanup_pod() {
  local pod_name="$1"
  kubectl -n "$NS" delete pod "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS" delete aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
}
