#!/usr/bin/env bash
# Task 12 follow-up: bring G1's file/network reps from n=15 up to the
# same n=30 target exec already met (the original n=15 was an explicitly
# documented scope reduction, not an error -- see exclusions.md; this
# closes that gap). Requests 15 MORE file+network reps from g1-runner
# (--reps-exec=0 skips exec, already at target), then merges them into
# the ORIGINAL raw/g1-results.json (rep numbers offset by +15 so they
# don't collide with the original reps 1-15) rather than overwriting it
# -- the original 120 records remain fully intact and traceable via git
# history (commit e0109d0), per experiment protocol rule 21.
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
NS=workloads
RUN_NAME="g1-bump-fn-$RANDOM"
G1_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/g1-runner:task10-v3"
OUT_DIR="$REPO_ROOT/artifacts/experiments/bpf-lsm/raw"
WORKER_NODE="vm-a2-cpucampaign-20260813-worker"

echo "=== creating g1-runner pod $RUN_NAME (file/network reps 16-30 only) ==="
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
      args: ["--bootstrap-wait=25s", "--reps-exec=0", "--reps-file=15", "--reps-network=15"]
EOF

echo "=== waiting for pod to be scheduled ==="
pod_uid="" node_name=""
for _ in $(seq 1 60); do
  pod_uid="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  node_name="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
  [ -n "$pod_uid" ] && [ -n "$node_name" ] && break
  sleep 0.5
done
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
echo "$decision_yaml" | kubectl apply -f - >/dev/null
kubectl -n "$NS" patch aiplacementdecision "$RUN_NAME" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null 2>&1

echo "=== waiting for operator to derive RuntimeSecurityPolicy/$RUN_NAME ==="
for _ in $(seq 1 60); do
  kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" >/dev/null 2>&1 && break
  sleep 0.5
done

echo "=== patching policy to enforce mode with G1's narrow allow-lists ==="
kubectl -n "$NS" patch runtimesecuritypolicy "$RUN_NAME" --type=merge -p '{
  "spec": {
    "enforcementMode": "enforce",
    "exec": {"defaultAction": "deny", "allowedPaths": ["/bin/true"]},
    "fileAccess": {"defaultAction": "deny", "allowedPathPrefixes": ["/tmp/allowed-testfile"]},
    "networkEgress": {"defaultAction": "deny", "allowedCIDRs": ["127.0.0.1/32"], "allowedPorts": [9999]}
  }
}' >/dev/null

echo "=== waiting for g1-runner to complete ==="
for _ in $(seq 1 96); do
  phase="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ] && break
  sleep 2.5
done
echo "final pod phase: $phase"

kubectl -n "$NS" logs "$RUN_NAME" | tail -1 > "$OUT_DIR/g1-results-$RUN_NAME.json"
kubectl -n "$NS" logs "$RUN_NAME" > "$OUT_DIR/g1-runner-full-log-$RUN_NAME.txt"

echo "=== merging into raw/g1-results.json (rep numbers offset +15) ==="
python3 - "$OUT_DIR/g1-results-$RUN_NAME.json" "$OUT_DIR/g1-results.json" <<'PYEOF'
import json, sys
new_path, main_path = sys.argv[1], sys.argv[2]
with open(new_path) as f:
    new_records = json.load(f)
with open(main_path) as f:
    main_records = json.load(f)
for r in new_records:
    r["rep"] = r["rep"] + 15  # original file/network reps were 1-15
main_records.extend(new_records)
with open(main_path, "w") as f:
    json.dump(main_records, f, indent=2)
print(f"merged {len(new_records)} new records; g1-results.json now has {len(main_records)} total")
PYEOF

echo "=== cleanup ==="
kubectl -n "$NS" delete pod "$RUN_NAME" --wait=false --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete runtimesecuritypolicy "$RUN_NAME" --wait=false --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete aiplacementdecision "$RUN_NAME" --wait=false --ignore-not-found >/dev/null 2>&1

echo "=== done ==="
