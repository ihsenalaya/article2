#!/usr/bin/env bash
# Phase 4: reintroduce RuntimeGuard's real pipeline end to end.
# D -> derive(D) -> P -> node agent -> cgroup/workload identity -> eBPF map -> BPF-LSM -> operation.
# Deliberately does NOT hand-patch RuntimeSecurityPolicy directly (that is exactly the
# tampering pattern Task 11's worker-side trust validation is designed to reject, and
# Task 12 already found this the hard way). Instead, mint-test-decision's new
# --exec-* flags let D itself request the enforce+allow policy, so P is a REAL
# derive(D) output whose hash the worker will actually accept.
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
TF_DIR="$REPO_ROOT/deploy/azure/cpu-campaign-20260813"
export KUBECONFIG="$TF_DIR/.run/kubeconfig"
NS="workloads"
RUN_NAME="phase4-exec-test-$(date +%s)"
WORKER_NODE="vm-a2-cpucampaign-20260813-worker"
G1_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/g1-runner:task10-v3"

SSH_KEY="$HOME/.ssh/article2_cpucampaign_ed25519"
WORKER_IP="$(terraform -chdir="$TF_DIR" output -raw worker_public_ip)"
WORKER_PRIVATE_IP="$(terraform -chdir="$TF_DIR" output -raw worker_private_ip)"
# Real listeners on the worker itself (started separately, outside any
# enforced pod) on both ports -- so DENY is a meaningful test (a policy bug
# would show up as an actual successful connection, not just an ambiguous
# "connection refused" from nothing listening).

echo "run_name=$RUN_NAME"

echo "=== cleanup any stale objects from a prior attempt ==="
kubectl -n "$NS" delete pod "$RUN_NAME" --wait=true --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete runtimesecuritypolicy "$RUN_NAME" --wait=true --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete aiplacementdecision "$RUN_NAME" --wait=true --ignore-not-found >/dev/null 2>&1

echo "=== 1) creating g1-runner pod (pinned to the worker node, real BPF-LSM) ==="
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $RUN_NAME
  namespace: $NS
  labels: { experiment: bpf-lsm-phased-20260815 }
spec:
  restartPolicy: Never
  nodeName: $WORKER_NODE
  imagePullSecrets:
    - name: acr-pull-secret
  containers:
    - name: g1-runner
      image: $G1_IMAGE
      args: ["--bootstrap-wait=20s", "--reps-exec=10", "--reps-file=10", "--reps-network=10", "--file-deny-target=/bin/true", "--network-allow-target=$WORKER_PRIVATE_IP:9999", "--network-deny-target=$WORKER_PRIVATE_IP:8888"]
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

echo "=== 2) minting signed decision D (signed ExecPolicyRequest + FilePolicyRequest + NetworkPolicyRequest) ==="
source "$TF_DIR/.run/secrets/trust-anchor.env"
decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
  --priv-key-hex "$PRIVATE_KEY_HEX" \
  --name "$RUN_NAME" --namespace "$NS" \
  --target-name "$RUN_NAME" --pod-uid "$pod_uid" --node-identity "$node_name" \
  --exec-enforcement-mode enforce \
  --exec-default-action deny \
  --exec-allowed-paths /bin/true \
  --file-default-action deny \
  --file-allowed-paths /lib/libm.so.6,/lib/libresolv.so.2,/lib/libc.so.6,/tmp/allowed-testfile \
  --network-default-action deny \
  --network-allowed-cidrs "$WORKER_PRIVATE_IP" \
  --network-allowed-ports 9999)"
if [ -z "$decision_yaml" ]; then
  echo "FAILED: mint-test-decision produced no output" >&2
  exit 1
fi
echo "$decision_yaml" > /tmp/phase4-decision.yaml
echo "$decision_yaml" | kubectl apply -f - >/dev/null
kubectl -n "$NS" patch aiplacementdecision "$RUN_NAME" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null

echo "=== 3) waiting for the operator to derive RuntimeSecurityPolicy/$RUN_NAME ==="
for _ in $(seq 1 60); do
  kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" >/dev/null 2>&1 && break
  sleep 0.5
done
echo "=== waiting for worker verification and the current policy generation to be applied ==="
for _ in $(seq 1 60); do
  generation="$(kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o jsonpath='{.metadata.generation}' 2>/dev/null || true)"
  applied_generation="$(kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o jsonpath='{.status.appliedPolicyGeneration}' 2>/dev/null || true)"
  verification="$(kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o jsonpath='{.status.verificationStatus}' 2>/dev/null || true)"
  if [ -n "$generation" ] && [ "$generation" = "$applied_generation" ] && [ "$verification" = "Verified" ]; then
    break
  fi
  sleep 0.5
done
if [ -z "${generation:-}" ] || [ "$generation" != "${applied_generation:-}" ] || [ "${verification:-}" != "Verified" ]; then
  echo "FAILED: current policy generation was not verified and applied" >&2
  exit 1
fi
echo "--- P (as actually derived by the real controller -- NOT hand-patched) ---"
kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o yaml > /tmp/phase4-derived-policy.yaml
kubectl -n "$NS" get runtimesecuritypolicy "$RUN_NAME" -o json > /tmp/phase4-derived-policy.json
cat /tmp/phase4-derived-policy.yaml

echo "=== 4) waiting for g1-runner pod to complete ==="
phase=""
for _ in $(seq 1 60); do
  phase="$(kubectl -n "$NS" get pod "$RUN_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ] && break
  sleep 3
done
echo "final pod phase: $phase"

echo "=== 5) g1-runner's own results ==="
kubectl -n "$NS" logs "$RUN_NAME" > /tmp/phase4-g1-runner-full-log.txt
kubectl -n "$NS" logs "$RUN_NAME" | tail -1 > /tmp/phase4-g1-results.json
cat /tmp/phase4-g1-results.json | python3 -m json.tool

python3 - /tmp/phase4-derived-policy.json /tmp/phase4-g1-results.json "$WORKER_PRIVATE_IP" <<'PY'
import json
import sys

policy = json.load(open(sys.argv[1], encoding="utf-8"))
rows = json.load(open(sys.argv[2], encoding="utf-8"))
worker_ip = sys.argv[3]

assert policy["status"]["verificationStatus"] == "Verified"
assert policy["status"]["appliedPolicyGeneration"] == policy["metadata"]["generation"]
assert policy["spec"]["enforcementMode"] == "enforce"
assert policy["spec"]["exec"] == {
    "allowedPaths": ["/bin/true"],
    "defaultAction": "deny",
}
assert policy["spec"]["fileAccess"] == {
    "allowedPathPrefixes": [
        "/lib/libm.so.6",
        "/lib/libresolv.so.2",
        "/lib/libc.so.6",
        "/tmp/allowed-testfile",
    ],
    "defaultAction": "deny",
}
assert policy["spec"]["networkEgress"] == {
    "allowedCIDRs": [worker_ip],
    "allowedPorts": [9999],
    "defaultAction": "deny",
}

allowed = [r for r in rows if r["op"] == "exec" and r["condition"] == "allow"]
denied = [r for r in rows if r["op"] == "exec" and r["condition"] == "deny"]
assert len(allowed) == 10 and len(denied) == 10
assert all(r["target"] == "/bin/true" and r["success"] and not r["errno_is_eperm"] for r in allowed)
assert all(
    r["target"] == "/bin/false"
    and not r["success"]
    and r["errno_is_eperm"]
    and not r["side_effect_observed"]
    for r in denied
)
file_allowed = [r for r in rows if r["op"] == "file" and r["condition"] == "allow"]
file_denied = [r for r in rows if r["op"] == "file" and r["condition"] == "deny"]
assert len(file_allowed) == 10 and len(file_denied) == 10
assert all(r["target"] == "/tmp/allowed-testfile" and r["success"] for r in file_allowed)
assert all(
    r["target"] == "/bin/true"
    and not r["success"]
    and r["errno_is_eperm"]
    and not r["side_effect_observed"]
    for r in file_denied
)
net_allowed = [r for r in rows if r["op"] == "network" and r["condition"] == "allow"]
net_denied = [r for r in rows if r["op"] == "network" and r["condition"] == "deny"]
assert len(net_allowed) == 10 and len(net_denied) == 10
# Real listeners on both ports (started outside any enforced pod) make this
# meaningful: ALLOW must actually reach the listener (a real TCP connect
# succeeding, not just "no EPERM"), and DENY must be blocked pre-connection
# (EPERM at connect() itself), not merely refused by an absent listener.
assert all(r["target"] == f"{worker_ip}:9999" and r["success"] and not r["errno_is_eperm"] for r in net_allowed)
assert all(
    r["target"] == f"{worker_ip}:8888"
    and not r["success"]
    and r["errno_is_eperm"]
    and not r["side_effect_observed"]
    for r in net_denied
)

print("PASS: exec, file, and network allow/deny all enforced as signed")
PY

echo "=== 6) independent kernel ground truth on the worker (bpftool), for THIS pod's actual cgroup ==="
ssh -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" azureuser@"$WORKER_IP" "
echo '--- container ID for this pod ---'
sudo crictl ps -a --name g1-runner -o json 2>/dev/null | python3 -c 'import json,sys; d=json.load(sys.stdin); [print(c[\"id\"], c[\"metadata\"][\"name\"]) for c in d.get(\"containers\",[])]' || true
"
