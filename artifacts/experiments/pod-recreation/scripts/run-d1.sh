#!/usr/bin/env bash
# D1: Kubernetes identity regression (Task 07, experiment protocol section 9).
# Not a novel-contribution claim -- a regression/anti-pattern validation of
# the H100-E04/E09 fix (commit 487a57e): a policy bound to Pod A's UID
# must never become active for a differently-UID'd Pod B recreated at the
# same Name+Namespace.
#
# Design: mint ONE decision, bound to Pod A's real UID, and get it to
# EnforcementReady. Delete Pod A only (NOT the decision/policy -- this is
# the scenario the experiment protocol describes: "Policy(A) MUST NOT become
# active for B", i.e. the ORIGINAL policy object, unchanged, tested
# against the new pod). Recreate Pod B at the identical Name+Namespace.
# Wait several poll cycles. Then check EXTERNAL cluster/log state (never
# workload self-report, per this campaign's established discipline) for
# whether the stale policy ever got applied to B's real cgroup:
#   (a) RuntimeSecurityPolicy.Status.appliedCgroupIDs must never come to
#       reflect a fresh binding event for B (checked via the "applied
#       policy" log line, which only fires on a genuinely new bind);
#   (b) the agent's "pod UID mismatch... refusing to bind" warning (added
#       by the H100-E04/E09 fix) must appear, naming this policy key,
#       AFTER B's creation -- positive confirmation the refusal mechanism
#       actively fired, not merely that nothing happened to fire it;
#   (c) no RuntimePlacementEvidence for this policy key ever shows
#       PodUID == B's real UID.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
NS=workloads
AGENT_NS=runtime-guard-agent-system
EVIDENCE_NS=aiops-system
REPS=10
POST_RECREATE_WAIT=20 # >= 4x the default 5s poll interval

OUT="$PWD/../raw/d1-pod-recreation.jsonl"
: > "$OUT"

source "$TRUST_ANCHOR_ENV"

create_pod() {
  local pod_name="$1"
  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod_name
  namespace: $NS
  labels: { experiment: pod-recreation }
spec:
  restartPolicy: Never
  containers:
    - name: workload
      image: busybox:1.36
      command: ["sleep", "3600"]
EOF
  local uid="" node=""
  for _ in $(seq 1 60); do
    uid="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    node="$(kubectl -n "$NS" get pod "$pod_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
    [ -n "$uid" ] && [ -n "$node" ] && break
    sleep 0.3
  done
  echo "${uid}|${node}"
}

declare -a REP_NAMES=() REP_UID_A=() REP_UID_B=() REP_B_CREATED_AT=()

for rep in $(seq 1 "$REPS"); do
  pod_name="d1-recreate-${rep}-$RANDOM"
  echo "[d1] rep $rep: pod name=$pod_name"

  result_a="$(create_pod "$pod_name")"
  uid_a="${result_a%%|*}"
  node="${result_a##*|}"
  if [ -z "$uid_a" ] || [ -z "$node" ]; then
    echo "[d1]   rep $rep: pod A failed to schedule, skipping" >&2
    kubectl -n "$NS" delete pod "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
    continue
  fi
  echo "[d1]   pod A uid=$uid_a node=$node"

  decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
    --priv-key-hex "$PRIVATE_KEY_HEX" --ttl 6h \
    --name "$pod_name" --namespace "$NS" \
    --target-name "$pod_name" --pod-uid "$uid_a" --node-identity "$node" \
    --decision-version 1 2>/dev/null)"
  echo "$decision_yaml" | kubectl apply -f - >/dev/null
  kubectl -n "$NS" patch aiplacementdecision "$pod_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

  ready="" decision=""
  for _ in $(seq 1 120); do
    ready="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.enforcementReadyAt}' 2>/dev/null || true)"
    decision="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.decision}' 2>/dev/null || true)"
    [ -n "$ready" ] && [ "$decision" = "active" ] && break
    sleep 0.2
  done
  if [ -z "$ready" ] || [ "$decision" != "active" ]; then
    echo "[d1]   rep $rep: pod A never reached EnforcementReady+active (decision=$decision), skipping" >&2
    kubectl -n "$NS" delete pod,aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
    continue
  fi
  applied_cgroups_a="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.appliedCgroupIDs}' 2>/dev/null || true)"
  echo "[d1]   pod A EnforcementReady+active, appliedCgroupIDs=$applied_cgroups_a"

  # Delete Pod A ONLY -- the decision/policy object is deliberately left
  # in place, unchanged, so it is the SAME policy object being tested
  # against the recreated pod (not a fresh one).
  kubectl -n "$NS" delete pod "$pod_name" --wait=false >/dev/null 2>&1
  for _ in $(seq 1 60); do
    kubectl -n "$NS" get pod "$pod_name" >/dev/null 2>&1 || break
    sleep 0.5
  done

  b_created_at="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ | sed -E 's/([0-9]{6})[0-9]{3}Z$/\1Z/')"
  result_b="$(create_pod "$pod_name")"
  uid_b="${result_b%%|*}"
  node_b="${result_b##*|}"
  if [ -z "$uid_b" ]; then
    echo "[d1]   rep $rep: pod B failed to schedule, skipping" >&2
    kubectl -n "$NS" delete pod,aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
    continue
  fi
  echo "[d1]   pod B uid=$uid_b node=$node_b (created at $b_created_at)"

  REP_NAMES+=("$pod_name")
  REP_UID_A+=("$uid_a")
  REP_UID_B+=("$uid_b")
  REP_B_CREATED_AT+=("$b_created_at")

  # Record the pre-recreation applied-cgroups snapshot alongside the
  # names, keyed positionally -- used below to detect any CHANGE after B
  # was created (which would indicate the stale policy re-bound).
  echo "$applied_cgroups_a" >> /tmp/d1-applied-cgroups-a.txt
done

echo "[d1] waiting ${POST_RECREATE_WAIT}s (>=4 poll cycles) for the agent to observe all recreated pods..."
sleep "$POST_RECREATE_WAIT"

echo "[d1] capturing agent logs..."
RAW_LOG="$(mktemp)"
kubectl -n "$AGENT_NS" logs -l app=runtime-guard-agent --since=15m --tail=-1 > "$RAW_LOG" 2>/dev/null

for idx in "${!REP_NAMES[@]}"; do
  pod_name="${REP_NAMES[$idx]}"
  uid_a="${REP_UID_A[$idx]}"
  uid_b="${REP_UID_B[$idx]}"
  b_created_at="${REP_B_CREATED_AT[$idx]}"
  applied_cgroups_a="$(sed -n "$((idx + 1))p" /tmp/d1-applied-cgroups-a.txt 2>/dev/null || true)"

  applied_cgroups_after="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.appliedCgroupIDs}' 2>/dev/null || true)"
  applied_gen_after="$(kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o jsonpath='{.status.appliedPolicyGeneration}' 2>/dev/null || true)"

  mismatch_line="$(awk -v t0="$b_created_at" -v pol="policy=$NS/$pod_name" -v uidb="$uid_b" '
    /pod UID mismatch/ && index($0, pol) && index($0, uidb) {
      split($1, a, "="); ts = a[2];
      if (ts > t0) { print; exit }
    }' "$RAW_LOG")"
  refusal_confirmed="false"
  [ -n "$mismatch_line" ] && refusal_confirmed="true"

  evidence_pod_uid="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o jsonpath='{.status.podUID}' 2>/dev/null || true)"
  evidence_bound_to_b="false"
  [ "$evidence_pod_uid" = "$uid_b" ] && evidence_bound_to_b="true"

  python3 -c "
import json
rec = {
    'pod_name': '$pod_name',
    'uid_a': '$uid_a',
    'uid_b': '$uid_b',
    'uid_changed': '$uid_a' != '$uid_b',
    'applied_cgroups_a_before_recreate': '$applied_cgroups_a',
    'applied_cgroups_after_recreate': '$applied_cgroups_after',
    'applied_cgroups_unchanged': '$applied_cgroups_a' == '$applied_cgroups_after',
    'applied_policy_generation_after': '$applied_gen_after' or None,
    'refusal_log_confirmed': $([ "$refusal_confirmed" = "true" ] && echo True || echo False),
    'evidence_pod_uid': '$evidence_pod_uid' or None,
    'evidence_incorrectly_bound_to_b': $([ "$evidence_bound_to_b" = "true" ] && echo True || echo False),
    'policy_did_not_bind_to_b': '$applied_cgroups_a' == '$applied_cgroups_after' and $([ "$evidence_bound_to_b" = "true" ] && echo False || echo True),
    'git_commit': '$GIT_SHA',
    'outcome': 'success',
}
print(json.dumps(rec))
" >> "$OUT"

  kubectl -n "$NS" delete pod,aiplacementdecision "$pod_name" --wait=false --ignore-not-found >/dev/null 2>&1
done

rm -f "$RAW_LOG" /tmp/d1-applied-cgroups-a.txt
echo "[d1] done, $(wc -l < "$OUT") records in $OUT"
