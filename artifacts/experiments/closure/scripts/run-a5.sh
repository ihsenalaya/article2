#!/usr/bin/env bash
# A5: no-policy negative control. No decision/policy is ever created for
# this pod. Determines externally (not from workload self-report) whether
# the workload attempted/achieved its operation, and whether the system
# produced ANY observation record for it.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"

N="${1:-10}"
OUT="$PWD/../raw/a5-no-policy-control.jsonl"
: > "$OUT"
ns=workloads

for i in $(seq 1 "$N"); do
  run_name="closure-a5-$(printf '%03d' "$i")-$RANDOM"
  echo "[a5] run $i/$N: $run_name"

  kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $run_name
  namespace: $ns
  labels: { experiment: closure, condition: "a5-no-policy" }
spec:
  restartPolicy: Never
  containers:
    - name: workload
      image: busybox:1.36
      command: ["sh", "-c"]
      args:
        - |
          if wget -T2 -q -O /dev/null http://closure-target-svc.workloads.svc.cluster.local/; then
            echo "WORKLOAD_OPERATION_RESULT=succeeded"
          else
            echo "WORKLOAD_OPERATION_RESULT=failed"
          fi
          sleep 3600
EOF

  sleep 10
  workload_log="$(kubectl -n "$ns" logs "$run_name" -c workload 2>/dev/null || true)"
  policy_exists="false"
  kubectl -n "$ns" get runtimesecuritypolicy "$run_name" >/dev/null 2>&1 && policy_exists="true"
  evidence_exists="false"
  kubectl -n aiops-system get runtimeplacementevidence "$run_name" >/dev/null 2>&1 && evidence_exists="true"

  workload_result="unknown"
  echo "$workload_log" | grep -q "WORKLOAD_OPERATION_RESULT=succeeded" && workload_result="succeeded"
  echo "$workload_log" | grep -q "WORKLOAD_OPERATION_RESULT=failed" && workload_result="failed"

  python3 -c "
import json
print(json.dumps({
    'run_id': '$run_name', 'condition': 'a5-no-policy', 'git_commit': '$GIT_SHA',
    'workload_self_reported_result': '$workload_result',
    'runtimesecuritypolicy_exists': $([ "$policy_exists" = "true" ] && echo True || echo False),
    'runtimeplacementevidence_exists': $([ "$evidence_exists" = "true" ] && echo True || echo False),
}))
" >> "$OUT"

  kubectl -n "$ns" delete pod "$run_name" --wait=false --ignore-not-found >/dev/null 2>&1
done
echo "[a5] done, $(wc -l < "$OUT") records in $OUT"
