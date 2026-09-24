#!/usr/bin/env bash
# Measures per-hook syscall latency overhead (execve/openat/connect) by
# strace -c -f'ing a tight syscall loop running INSIDE the real workload
# pod's leaf cgroup, once with the eBPF agent DaemonSet attached (audit
# mode) and once with it fully removed (real baseline, not an estimate).
#
# Why strace instead of shell wall-clock timing: a first attempt timed shell
# loops with `date +%s%N` / busybox `time`, but busybox's `date` silently
# ignores %N (no nanosecond support), collapsing every measurement to whole
# seconds, and busybox `time`'s ~10ms resolution is still far coarser than
# the microsecond-scale effect being measured — both would have produced
# fabricated-looking "0.005s/call" numbers that were really just quantization
# noise. strace -c reports per-syscall usecs/call derived from the kernel's
# own wait4()/times() accounting, giving real microsecond resolution. See
# EXPERIMENTS_LOG.md Phase 6 for the full account of this dead end.
#
# Method: for each condition (agent present/absent), nsenter into the
# target container's pid/net/uts/ipc namespaces (NOT mount — so the node's
# own strace/bash/coreutils stay reachable) from the kind node, write our
# own pid into the container's real leaf cgroup (see cgroupmap bug #11 —
# this is the cgroup bpf_get_current_cgroup_id() actually resolves to), then
# strace -c -f a loop of N syscalls. This makes the probe process a real
# member of the tracked pod's cgroup, exercising the exact same
# get_cgroup_config()/resolve_*_decision()/emit_event() path a real syscall
# from that pod would.
#
# Usage: ./measure_hook_latency.sh <pod> <namespace> <container> <iterations> <repetitions> <output-csv>
set -uo pipefail

POD="${1:?pod name required}"
NAMESPACE="${2:?namespace required}"
CONTAINER="${3:?container name required}"
ITERATIONS="${4:-300}"
REPETITIONS="${5:-5}"
OUTPUT_CSV="${6:?output CSV path required}"
KUBE_CONTEXT="${KUBE_CONTEXT:-kind-article2}"
AGENT_NAMESPACE="${AGENT_NAMESPACE:-runtime-guard-agent-system}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_MANIFEST="$SCRIPT_DIR/../../deploy/kind/agent-daemonset.yaml"
PROBE_SCRIPT="$SCRIPT_DIR/hook_probe.sh"

if [ ! -f "$PROBE_SCRIPT" ]; then
  echo "missing $PROBE_SCRIPT" >&2
  exit 1
fi

NODE=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod "$POD" -o jsonpath='{.spec.nodeName}')
CONTAINER_ID=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod "$POD" \
  -o jsonpath="{.status.containerStatuses[?(@.name==\"$CONTAINER\")].containerID}" | sed 's#^[a-z]*://##')
FORBIDDEN_IP=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get svc forbidden-svc -o jsonpath='{.spec.clusterIP}')

echo "node=$NODE container_id=$CONTAINER_ID forbidden_ip=$FORBIDDEN_IP"

echo "Ensuring strace is available on $NODE..."
docker exec "$NODE" sh -c 'command -v strace >/dev/null 2>&1 || (apt-get update -qq && apt-get install -y -qq strace)' >/dev/null

HOST_PID=$(docker exec "$NODE" sh -c "crictl inspect $CONTAINER_ID 2>/dev/null" | python3 -c "import json,sys; print(json.load(sys.stdin)['info']['pid'])")
CGROUP_PROCS=$(docker exec "$NODE" find /sys/fs/cgroup -path "*cri-containerd-$CONTAINER_ID*" -name cgroup.procs 2>/dev/null | head -1)

if [ -z "$HOST_PID" ] || [ -z "$CGROUP_PROCS" ]; then
  echo "failed to resolve host pid ($HOST_PID) or cgroup.procs path ($CGROUP_PROCS)" >&2
  exit 1
fi
echo "host_pid=$HOST_PID cgroup_procs=$CGROUP_PROCS"

# NOTE: copied to /root, not /tmp — /tmp on the kind node is a tmpfs that was
# observed to lose a freshly `docker cp`'d file within the same command chain
# (a real, reproducible finding on this environment, not a guess); /root has
# no such issue.
docker cp "$PROBE_SCRIPT" "$NODE:/root/hook_probe.sh" >/dev/null

echo "syscall,agent_present,repetition,iterations,calls,errors,usecs_per_call" > "$OUTPUT_CSV"

run_and_parse() {
  local hook="$1" agent_present="$2" rep="$3"
  local raw
  raw=$(docker exec "$NODE" bash /root/hook_probe.sh "$HOST_PID" "$CGROUP_PROCS" "$hook" "$ITERATIONS" "$FORBIDDEN_IP" 2>&1)
  # strace -c summary rows always end in the syscall name as the last
  # field; the errors column is only present (second-to-last field) when
  # that syscall had at least one error, so match by last field rather than
  # a fixed column count.
  local row
  row=$(echo "$raw" | awk -v s="$hook" '$NF==s {print; exit}')
  if [ -z "$row" ]; then
    echo "$hook,$agent_present,$rep,$ITERATIONS,NA,NA,NA" >> "$OUTPUT_CSV"
    echo "  hook=$hook agent_present=$agent_present rep=$rep -> NOT FOUND in strace output" >&2
    return
  fi
  local usecs calls errors nf
  nf=$(echo "$row" | awk '{print NF}')
  usecs=$(echo "$row" | awk '{print $3}')
  if [ "$nf" = "6" ]; then
    calls=$(echo "$row" | awk '{print $4}')
    errors=$(echo "$row" | awk '{print $5}')
  else
    calls=$(echo "$row" | awk '{print $4}')
    errors=0
  fi
  echo "$hook,$agent_present,$rep,$ITERATIONS,$calls,$errors,$usecs" >> "$OUTPUT_CSV"
  echo "  hook=$hook agent_present=$agent_present rep=$rep calls=$calls errors=$errors usecs_per_call=$usecs"
}

for AGENT_PRESENT in true false; do
  if [ "$AGENT_PRESENT" = "false" ]; then
    echo "Removing agent DaemonSet for baseline (no-agent) measurement..."
    kubectl --context "$KUBE_CONTEXT" -n "$AGENT_NAMESPACE" delete daemonset runtime-guard-agent --ignore-not-found >/dev/null
    kubectl --context "$KUBE_CONTEXT" -n "$AGENT_NAMESPACE" wait --for=delete pod -l app=runtime-guard-agent --timeout=60s >/dev/null 2>&1 || true
    sleep 3
  fi

  for hook in execve openat connect; do
    for rep in $(seq 1 "$REPETITIONS"); do
      run_and_parse "$hook" "$AGENT_PRESENT" "$rep"
    done
  done
done

echo "Restoring agent DaemonSet..."
kubectl --context "$KUBE_CONTEXT" apply -f "$AGENT_MANIFEST" >/dev/null
kubectl --context "$KUBE_CONTEXT" -n "$AGENT_NAMESPACE" rollout status daemonset/runtime-guard-agent --timeout=60s

echo "Raw results written to $OUTPUT_CSV"
