#!/usr/bin/env bash
# A4: NON-COOPERATIVE workload control (mandatory). A signed decision/policy
# IS created (so t_p is real and comparable to A1), but the workload does
# NOT run the launcher, does NOT wait for EnforcementReady, does NOT check a
# ready-file. It attempts its critical operation immediately at container
# start. Determines experimentally whether the release mechanism is a real
# barrier or bypassable.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"

N="${1:-10}"
OUT="$PWD/../raw/a4-noncooperative.jsonl"
: > "$OUT"
ns=workloads

for i in $(seq 1 "$N"); do
  run_name="closure-a4-$(printf '%03d' "$i")-$RANDOM"
  echo "[a4] run $i/$N: $run_name"
  start_wall="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $run_name
  namespace: $ns
  labels: { experiment: closure, condition: "a4-noncooperative" }
spec:
  restartPolicy: Never
  containers:
    - name: workload
      image: busybox:1.36
      command: ["sh", "-c"]
      args:
        - |
          wget -T2 -q -O /dev/null http://closure-target-svc.workloads.svc.cluster.local/ || true
          sleep 3600
EOF

  pod_uid="" node_name=""
  for _ in $(seq 1 60); do
    pod_uid="$(kubectl -n "$ns" get pod "$run_name" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
    node_name="$(kubectl -n "$ns" get pod "$run_name" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
    [ -n "$pod_uid" ] && [ -n "$node_name" ] && break
    sleep 0.2
  done

  # Mint+apply the decision AFTER pod creation, same as A1/A2/A3 -- but the
  # workload does not wait for it at all, so the race is entirely
  # uncontrolled from the workload's side. This models the realistic case
  # where the decision is minted around pod admission time.
  decision_yaml=""
  if [ -n "$pod_uid" ] && [ -n "$node_name" ]; then
    source "$TRUST_ANCHOR_ENV"
    decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
      --priv-key-hex "$PRIVATE_KEY_HEX" \
      --name "$run_name" --namespace "$ns" \
      --target-name "$run_name" --pod-uid "$pod_uid" --node-identity "$node_name" 2>/dev/null)"
    if [ -n "$decision_yaml" ]; then
      echo "$decision_yaml" | kubectl apply -f - >/dev/null
      kubectl -n "$ns" patch aiplacementdecision "$run_name" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1
    fi
  fi

  # Give the system a real window to observe/apply/react, then snapshot.
  sleep 12
  policy_json="$(kubectl -n "$ns" get runtimesecuritypolicy "$run_name" -o json 2>/dev/null || echo '{}')"
  workload_log="$(kubectl -n "$ns" logs "$run_name" -c workload 2>/dev/null || true)"
  end_wall="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"

  POLICY_JSON="$policy_json" WORKLOAD_LOG="$workload_log" python3 - "$run_name" "$pod_uid" "$node_name" "$start_wall" "$end_wall" "$GIT_SHA" <<'PYEOF' >> "$OUT"
import json, sys, os
run_name, pod_uid, node_name, start_wall, end_wall, git_sha = sys.argv[1:7]
policy_raw = os.environ.get("POLICY_JSON", "{}")
try:
    policy = json.loads(policy_raw)
except Exception:
    policy = {}
status = policy.get("status", {})
rec = {
    "run_id": run_name, "condition": "a4-noncooperative", "pod_uid": pod_uid,
    "node_name": node_name, "start_wall": start_wall, "end_wall": end_wall,
    "git_commit": git_sha,
    "enforcement_ready_monotonic_ns": status.get("enforcementReadyMonotonicNs"),
    "first_observed_operation_monotonic_ns": status.get("firstObservedOperationMonotonicNs"),
    "applied_policy_generation": status.get("appliedPolicyGeneration"),
    "evidence_mode": status.get("evidenceMode"),
}
tp = rec["enforcement_ready_monotonic_ns"]
tc = rec["first_observed_operation_monotonic_ns"]
if tp is not None and tc is not None:
    rec["operation_observed_before_policy_ready"] = tc < tp
print(json.dumps(rec))
PYEOF

  kubectl -n "$ns" delete pod "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
  kubectl -n "$ns" delete aiplacementdecision "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
done
echo "[a4] done, $(wc -l < "$OUT") records in $OUT"
