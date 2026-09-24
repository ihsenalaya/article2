#!/usr/bin/env bash
# Shared helpers for Experiment B (Task 05, observation completeness).
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
NS=workloads

# create_policy_bound_pod <pod_name> <image> <tool_name> <tool_args...>
# Creates a pod running /usr/local/bin/<tool_name> <tool_args...> then
# sleeping for POD_LINGER_SECONDS (default 90s) before exiting (NOT the
# observation-tools image's default ENTRYPOINT ["sleep","3600"] -- an empty
# `command: []` was tried and does NOT override ENTRYPOINT, so `command`
# must be set explicitly), mints+applies a real signed decision for it once
# scheduled, and waits for EnforcementReady. Echoes nothing; caller inspects
# the cluster directly afterward.
#
# The trailing sleep is not cosmetic: it keeps the pod's cgroup alive past
# tool completion. Without it, a short-lived tool exits, the pod goes
# Completed, and the agent's reconcile loop can race ahead to revoke +
# forgetAll (which wipes per-cgroup counters outright) before the next
# evidence-emission tick ever fires -- silently zeroing out
# observed_in_evidence for reasons that have nothing to do with eBPF
# observation coverage. This was discovered via a B1 run at rate=1000/s that
# showed 100% loss (0/10000 observed) while rate=100/s showed 36.7% loss --
# a jump inconsistent with any rate-dependent mechanism, and consistent with
# this capture race instead.
POD_LINGER_SECONDS="${POD_LINGER_SECONDS:-90}"

# GATE_START=1 makes the tool wait for /tmp/start-generating before running,
# and create_policy_bound_pod touches that file (via kubectl exec) only
# after EnforcementReady is confirmed. Without this, the tool starts
# generating load at container start -- which races ahead of (and can
# substantially overlap with) the harness's own decision-minting and
# EnforcementReady wait, confounding rate-dependent observation loss with
# Task 04's admission-to-release closure gap. This was discovered because
# B1's rate=100 run (first in the sweep, plausibly a colder start) showed
# consistently higher loss (~60%) than later rates (~20-31%) even after the
# capture-race fix above -- a pattern consistent with a variable closure-gap
# overlap, not a rate effect. Opt-in (not default) since B2/B3 are less
# sensitive to this and gating adds a kubectl exec round-trip.
GATE_START="${GATE_START:-0}"

create_policy_bound_pod() {
  local pod_name="$1" image="$2" tool_name="$3"
  shift 3
  local args_json
  args_json="$(printf '%s\n' "$@" | python3 -c "import json,sys; print(json.dumps([l.rstrip(chr(10)) for l in sys.stdin]))")"

  local inner_cmd="\"\$0\" \"\$@\"; sleep $POD_LINGER_SECONDS"
  if [ "$GATE_START" = "1" ]; then
    inner_cmd="while [ ! -f /tmp/start-generating ]; do sleep 0.2; done; $inner_cmd"
  fi

  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  namespace: $NS
  labels: { experiment: observation-completeness }
spec:
  serviceAccountName: closure-test-runner
  restartPolicy: Never
  imagePullSecrets:
    - name: acr-pull-secret
  containers:
    - name: workload
      image: $image
      command: ["sh", "-c", '$inner_cmd', "/usr/local/bin/$tool_name"]
      args: $args_json
EOF

  local pod_uid="" node_name=""
  for _ in $(seq 1 60); do
    pod_uid="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    node_name="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
    [ -n "$pod_uid" ] && [ -n "$node_name" ] && break
    sleep 0.3
  done
  if [ -z "$pod_uid" ] || [ -z "$node_name" ]; then
    echo "ERROR: $pod_name did not schedule" >&2
    return 1
  fi

  source "$TRUST_ANCHOR_ENV"
  local decision_yaml
  decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
    --priv-key-hex "$PRIVATE_KEY_HEX" \
    --name "$pod_name" --namespace "$NS" \
    --target-name "$pod_name" --pod-uid "$pod_uid" --node-identity "$node_name" 2>/dev/null)"
  echo "$decision_yaml" | kubectl apply -f - >/dev/null
  kubectl -n "$NS" patch aiplacementdecision "$pod_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

  for _ in $(seq 1 60); do
    local ready
    ready="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.enforcementReadyAt}' 2>/dev/null || true)"
    if [ -n "$ready" ]; then
      if [ "$GATE_START" = "1" ]; then
        kubectl -n "$NS" exec "$pod_name" -c workload -- touch /tmp/start-generating >/dev/null 2>&1
      fi
      return 0
    fi
    sleep 0.5
  done
  echo "ERROR: $pod_name policy never became ready" >&2
  return 1
}

cleanup_pod() {
  local pod_name="$1"
  kubectl -n "$NS" delete pod "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
  kubectl -n "$NS" delete aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
}
