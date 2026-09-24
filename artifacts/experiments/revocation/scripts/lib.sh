#!/usr/bin/env bash
# Shared helpers for Experiment C (Task 06, revocation and evidence
# semantics). Reuses a single long-running policy-bound pod across many
# revoke/reauthorize cycles (mirrors experiments/metrics/measure_revocation.sh's
# proven pattern) rather than recreating a pod per trial, since C1/C2 need
# tens of trials per polling-interval condition and pod scheduling overhead
# would dominate wall-clock time otherwise.
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
NS=workloads
AGENT_NS=runtime-guard-agent-system
EVIDENCE_NS=aiops-system
AGENT_PUB_KEY_HEX="$(grep PUBLIC_KEY_HEX "$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/agent-signing.env" | cut -d= -f2)"

# create_longrunning_pod <pod_name> -- a plain busybox pod that just stays
# alive (no event generation needed for C1/C2/C3; revocation timing does
# not depend on workload activity). Returns pod UID/node via globals
# POD_UID/NODE_NAME.
create_longrunning_pod() {
  local pod_name="$1"
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  namespace: $NS
  labels: { experiment: revocation }
spec:
  restartPolicy: Never
  containers:
    - name: workload
      image: busybox:1.36
      command: ["sleep", "3600"]
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
}

# mint_and_authorize <pod_name> <decision_version> -- mints and applies a
# fresh signed AIPlacementDecision at the given (must be increasing)
# version -- the anti-replay ledger rejects a same-version reauthorization
# (see decision_ledger.go; this is the exact bug commit 487a57e's
# companion script fix addressed), waits for EnforcementReady.
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
    # enforcementReadyAt alone is NOT sufficient: the agent applies
    # whatever Spec exists and marks EnforcementReady regardless of
    # whether the OPERATOR verified/accepted the decision (confirmed by
    # Task 00's audit -- the agent never reads
    # RuntimeSecurityPolicy.Status.Decision at all). A decision REJECTED
    # by the anti-replay ledger (e.g. reusing a decision_id+version this
    # ledger has already seen -- which happens across separate script
    # invocations sharing the same hardcoded pod name, since the ledger
    # is a persistent ConfigMap, not tied to the K8s object's own
    # lifecycle) still gets enforcementReadyAt set, but with an EMPTY
    # Spec.Binding/Spec.Derivation, silently producing evidence with
    # blank DecisionID/DecisionHash/PolicyHash and, if signed against
    # inconsistent captured state, a payload digest mismatch on
    # verification. Found via exactly this failure mode in C3 (Task 06).
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

# set_poll_interval <duration> -- patches the agent DaemonSet's
# --poll-interval and waits for the rollout to complete on both nodes.
set_poll_interval() {
  local interval="$1"
  kubectl -n "$AGENT_NS" patch daemonset runtime-guard-agent --type=json \
    -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/containers/0/args\",\"value\":[\"--poll-interval=${interval}\"]}]" >/dev/null
  kubectl -n "$AGENT_NS" rollout status daemonset/runtime-guard-agent --timeout=120s >/dev/null 2>&1
}

# set_watch_revocation <true|false> -- toggles the agent's opt-in
# watch-based revocation path (Task 06/C2) and waits for rollout.
set_watch_revocation() {
  local enabled="$1"
  kubectl -n "$AGENT_NS" set env daemonset/runtime-guard-agent WATCH_REVOCATION="$enabled" >/dev/null
  kubectl -n "$AGENT_NS" rollout status daemonset/runtime-guard-agent --timeout=120s >/dev/null 2>&1
}

cleanup_pod() {
  local pod_name="$1"
  kubectl -n "$NS" delete pod "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS" delete aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
}
