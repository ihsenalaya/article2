#!/usr/bin/env bash
# One-time setup for the BPF-LSM enforcement-path microbenchmark: creates a
# single long-running "bench-pod" (perf-workload image, sleep infinity),
# mints ONE signed decision granting enforce mode + ALLOW for exactly the
# three benchmarked targets (exec /bin/true, file /etc/hostname, network
# 127.0.0.1:1 -- same targets/rationale as the existing F1 experiment, see
# ../../performance/experiment-config.json's network_op_semantics), and
# waits for EnforcementReady. Left running for the whole benchmark: C1/C2/C3
# never re-derive D->P (that's what keeps condition switches cheap), only
# --benchmark-mode-enabled's local control channel (set via cmd/agent's
# opt-in flag) toggles between them.
#
# Prints (as `export` lines to stdout, source this script's output or the
# script itself with `. setup.sh`): BENCH_POD, AGENT_POD (the runtime-guard-
# agent pod on the SAME worker node, target of all benchmark-control
# commands), CGROUP_ID (bench-pod's applied cgroup ID), POLICY_GENERATION.
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
NS=workloads
AGENT_NS=runtime-guard-agent-system
WORKER_NODE="vm-a2-cpucampaign-20260813-worker"
WORKLOAD_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/perf-workload:task13-mem"
POD_NAME="bpf-lsm-bench-pod"

kubectl -n "$NS" delete pod "$POD_NAME" --wait=true --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete runtimesecuritypolicy "$POD_NAME" --wait=true --ignore-not-found >/dev/null 2>&1
kubectl -n "$NS" delete aiplacementdecision "$POD_NAME" --wait=true --ignore-not-found >/dev/null 2>&1

echo "=== creating bench-pod (pinned to the worker node) ===" >&2
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $POD_NAME
  namespace: $NS
  labels: { experiment: bpf-lsm-enforcement-overhead }
spec:
  restartPolicy: Never
  nodeName: $WORKER_NODE
  imagePullSecrets:
    - name: acr-pull-secret
  containers:
    - name: workload
      image: $WORKLOAD_IMAGE
      imagePullPolicy: Always
EOF

POD_UID="" NODE_NAME=""
for _ in $(seq 1 60); do
  POD_UID="$(kubectl -n "$NS" get pod "$POD_NAME" -o jsonpath='{.metadata.uid}' 2>/dev/null || true)"
  NODE_NAME="$(kubectl -n "$NS" get pod "$POD_NAME" -o jsonpath='{.spec.nodeName}' 2>/dev/null || true)"
  [ -n "$POD_UID" ] && [ -n "$NODE_NAME" ] && break
  sleep 0.3
done
if [ -z "$POD_UID" ] || [ -z "$NODE_NAME" ]; then
  echo "ERROR: $POD_NAME did not schedule" >&2
  exit 1
fi
for _ in $(seq 1 60); do
  phase="$(kubectl -n "$NS" get pod "$POD_NAME" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [ "$phase" = "Running" ] && break
  sleep 0.3
done

echo "=== minting signed decision (enforce + ALLOW exec/file/network targets) ===" >&2
source "$TRUST_ANCHOR_ENV"
decision_yaml="$(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
  --priv-key-hex "$PRIVATE_KEY_HEX" --ttl 6h \
  --name "$POD_NAME" --namespace "$NS" \
  --decision-version "$(date +%s)" \
  --target-name "$POD_NAME" --pod-uid "$POD_UID" --node-identity "$NODE_NAME" \
  --exec-enforcement-mode enforce \
  --exec-default-action allow \
  --exec-allowed-paths /bin/true \
  --file-default-action allow \
  --file-allowed-paths /etc/hostname \
  --network-default-action allow \
  --network-allowed-cidrs 127.0.0.1 \
  --network-allowed-ports 1)"
# Defaults are ALLOW, not deny: this is a latency microbenchmark, not a
# policy-correctness test (that is already covered by
# artifacts/experiments/bpf-lsm-20260815-phased/). A deny-by-default file
# policy blocks kubectl exec's OWN OCI runtime setup (it opens
# /proc/sys/kernel/cap_last_cap inside the target cgroup) -- the exact same
# conflict already documented in operator/cmd/g1-runner's package comment,
# which is why g1-runner runs as the pod's own entrypoint instead of via
# kubectl exec. This experiment still genuinely exercises the real
# exec_rules/file_rules/net_rules map lookup for each benchmarked target
# (each gets its own explicit --*-allowed-* rule entry, populated
# regardless of the default), which is what C2/C3 actually measure; the
# default only governs OTHER, incidental file/exec/connect activity
# (kubectl exec's own plumbing) that must not be accidentally blocked by
# this experiment's own instrumentation.
echo "$decision_yaml" | kubectl apply -f - >/dev/null
kubectl -n "$NS" patch aiplacementdecision "$POD_NAME" --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' >/dev/null

echo "=== waiting for EnforcementReady ===" >&2
CGROUP_ID="" POLICY_GENERATION=""
for _ in $(seq 1 120); do
  ready="$(kubectl -n "$NS" get runtimesecuritypolicy "$POD_NAME" -o jsonpath='{.status.enforcementReadyAt}' 2>/dev/null || true)"
  decision="$(kubectl -n "$NS" get runtimesecuritypolicy "$POD_NAME" -o jsonpath='{.status.decision}' 2>/dev/null || true)"
  verification="$(kubectl -n "$NS" get runtimesecuritypolicy "$POD_NAME" -o jsonpath='{.status.verificationStatus}' 2>/dev/null || true)"
  if [ -n "$ready" ] && [ "$decision" = "active" ] && [ "$verification" = "Verified" ]; then
    CGROUP_ID="$(kubectl -n "$NS" get runtimesecuritypolicy "$POD_NAME" -o jsonpath='{.status.appliedCgroupIDs[0]}')"
    POLICY_GENERATION="$(kubectl -n "$NS" get runtimesecuritypolicy "$POD_NAME" -o jsonpath='{.status.appliedPolicyGeneration}')"
    break
  fi
  if [ "$decision" = "rejected" ]; then
    reason="$(kubectl -n "$NS" get runtimesecuritypolicy "$POD_NAME" -o jsonpath='{.status.rejectionReason}' 2>/dev/null || true)"
    echo "ERROR: decision rejected: $reason" >&2
    exit 1
  fi
  sleep 0.5
done
if [ -z "$CGROUP_ID" ]; then
  echo "ERROR: policy never became ready+verified+active" >&2
  exit 1
fi

AGENT_POD="$(kubectl -n "$AGENT_NS" get pods -o wide --no-headers | awk -v n="$WORKER_NODE" '$7==n{print $1}')"
if [ -z "$AGENT_POD" ]; then
  echo "ERROR: could not find runtime-guard-agent pod on $WORKER_NODE" >&2
  exit 1
fi

echo "=== bench-pod ready: pod=$POD_NAME uid=$POD_UID cgroup=$CGROUP_ID generation=$POLICY_GENERATION agent_pod=$AGENT_POD ===" >&2

echo "export BENCH_POD=$POD_NAME"
echo "export BENCH_POD_UID=$POD_UID"
echo "export AGENT_POD=$AGENT_POD"
echo "export AGENT_NS=$AGENT_NS"
echo "export CGROUP_ID=$CGROUP_ID"
echo "export POLICY_GENERATION=$POLICY_GENERATION"
echo "export WORKER_NODE=$WORKER_NODE"
echo "export NS=$NS"
