#!/usr/bin/env bash
# Tetragon side-by-side comparison against the REAL Azure VM cluster, for
# TASK-14's expanded "Tetragon comparison uses the same real-VM environment"
# requirement. Derived from task12-tetragon-kind-baseline.sh but:
#   - does NOT re-run the internal task04-09 sub-campaign (already executed
#     directly against this same Azure cluster earlier in this session --
#     re-running here would be redundant, not a fresh comparison point);
#   - does NOT call the kind-specific final-kind-restore step;
#   - parameterizes the node name (real Azure VMs are not named
#     "article2-worker").
# The runtime-guard side of the comparison is instead read from the results
# already on disk (see RUNTIME_GUARD_SUMMARY_CSV below).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${TASK12_OUT_DIR:-$REPO_ROOT/results/tasks/TASK-14/azure-vm-scientific-campaign/tetragon-comparison}"

KUBE_CONTEXT="${KUBE_CONTEXT:?KUBE_CONTEXT required}"
NODE_NAME="${NODE_NAME:?NODE_NAME required}"
TETRAGON_NAMESPACE="${TETRAGON_NAMESPACE:-tetragon-baseline}"
WORKLOAD_NAMESPACE="${TASK12_WORKLOAD_NAMESPACE:-task14b-tetragon}"
TETRAGON_CHART_VERSION="${TETRAGON_CHART_VERSION:-1.7.0}"
SUMMARY_CSV="$OUT_DIR/raw-data/side-by-side-summary.csv"
TETRAGON_EVENTS_JSONL="$OUT_DIR/raw-data/tetragon-events.jsonl"
TETRAGON_NETWORK_EVENTS_JSONL="$OUT_DIR/raw-data/tetragon-tetra-network-events-filtered.jsonl"
TETRAGON_PODS_TXT="$OUT_DIR/raw-data/tetragon-pods.txt"

mkdir -p "$OUT_DIR/raw-data" "$OUT_DIR/stdout" "$OUT_DIR/stderr"

echo "system,case,expected,observed,result,raw_artifact" > "$SUMMARY_CSV"

record() {
  local system_name="$1" case_name="$2" expected="$3" observed="$4" result="$5" raw_artifact="$6"
  printf '%s,%s,"%s","%s",%s,%s\n' "$system_name" "$case_name" "$expected" "$observed" "$result" "$raw_artifact" >> "$SUMMARY_CSV"
  echo "system=$system_name case=$case_name result=$result observed=$observed"
}

require() { command -v "$1" >/dev/null 2>&1 || { echo "required command not found: $1" >&2; exit 127; }; }
require kubectl; require helm; require python3

echo "task=TASK-14-tetragon-comparison context=$KUBE_CONTEXT node=$NODE_NAME chart_version=$TETRAGON_CHART_VERSION"
kubectl --context "$KUBE_CONTEXT" cluster-info > "$OUT_DIR/raw-data/cluster-info.txt"
kubectl --context "$KUBE_CONTEXT" get nodes -o wide > "$OUT_DIR/raw-data/nodes-before.txt"

# Runtime-guard side: reuse this session's already-executed real-cluster
# results instead of re-running them (they are the same real environment).
RUNTIME_GUARD_ANTI_REPLAY_CSV="${RUNTIME_GUARD_ANTI_REPLAY_CSV:-}"
if [ -n "$RUNTIME_GUARD_ANTI_REPLAY_CSV" ] && [ -f "$RUNTIME_GUARD_ANTI_REPLAY_CSV" ]; then
  python3 - "$RUNTIME_GUARD_ANTI_REPLAY_CSV" "$SUMMARY_CSV" <<'PY'
import csv, sys
source_path, summary_path = sys.argv[1], sys.argv[2]
with open(source_path, newline="") as sf, open(summary_path, "a", newline="") as tf:
    reader = csv.DictReader(sf)
    writer = csv.writer(tf, lineterminator="\n")
    for row in reader:
        writer.writerow(["runtime-guard", row["case"], row.get("expected",""), row.get("actual",""), row.get("result",""), "azure-vm-scientific-campaign/anti-replay/results.csv"])
PY
fi

echo "installing clean Tetragon baseline on the real Azure VM cluster..."
helm --kube-context "$KUBE_CONTEXT" uninstall tetragon -n "$TETRAGON_NAMESPACE" >/dev/null 2>&1 || true
kubectl --context "$KUBE_CONTEXT" delete namespace "$TETRAGON_NAMESPACE" --ignore-not-found >/dev/null
kubectl --context "$KUBE_CONTEXT" delete namespace "$WORKLOAD_NAMESPACE" --ignore-not-found >/dev/null
kubectl --context "$KUBE_CONTEXT" delete tracingpolicy article2-baseline-comparison --ignore-not-found >/dev/null 2>&1 || true

helm repo add cilium https://helm.cilium.io >/dev/null 2>&1 || true
helm repo update cilium > "$OUT_DIR/stdout/helm-repo-update.out" 2> "$OUT_DIR/stderr/helm-repo-update.err"
helm --kube-context "$KUBE_CONTEXT" install tetragon cilium/tetragon \
  --version "$TETRAGON_CHART_VERSION" \
  --namespace "$TETRAGON_NAMESPACE" \
  --create-namespace \
  --wait \
  --timeout 5m \
  --set export.mode=stdout \
  > "$OUT_DIR/stdout/helm-install-tetragon.out" \
  2> "$OUT_DIR/stderr/helm-install-tetragon.err"

kubectl --context "$KUBE_CONTEXT" -n "$TETRAGON_NAMESPACE" rollout status daemonset/tetragon --timeout=180s \
  > "$OUT_DIR/stdout/tetragon-rollout.out" 2> "$OUT_DIR/stderr/tetragon-rollout.err"
kubectl --context "$KUBE_CONTEXT" -n "$TETRAGON_NAMESPACE" get pods -o wide > "$TETRAGON_PODS_TXT"
kubectl --context "$KUBE_CONTEXT" apply -f "$REPO_ROOT/deploy/kind/tetragon-baseline-policy.yaml" \
  > "$OUT_DIR/stdout/tetragon-policy-apply.out" 2> "$OUT_DIR/stderr/tetragon-policy-apply.err"
kubectl --context "$KUBE_CONTEXT" get tracingpolicy article2-baseline-comparison -o yaml \
  > "$OUT_DIR/raw-data/tetragon-policy-applied.yaml"

cat <<YAML | kubectl --context "$KUBE_CONTEXT" apply -f - > "$OUT_DIR/stdout/tetragon-workload-apply.out" 2> "$OUT_DIR/stderr/tetragon-workload-apply.err"
apiVersion: v1
kind: Namespace
metadata:
  name: $WORKLOAD_NAMESPACE
---
apiVersion: v1
kind: Service
metadata:
  name: forbidden-svc
  namespace: $WORKLOAD_NAMESPACE
spec:
  selector:
    app: forbidden-endpoint
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: forbidden-endpoint
  namespace: $WORKLOAD_NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: forbidden-endpoint
  template:
    metadata:
      labels:
        app: forbidden-endpoint
    spec:
      nodeSelector:
        kubernetes.io/hostname: $NODE_NAME
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports:
            - containerPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: tetragon-workload
  namespace: $WORKLOAD_NAMESPACE
  labels:
    app: tetragon-workload
spec:
  nodeSelector:
    kubernetes.io/hostname: $NODE_NAME
  restartPolicy: Never
  containers:
    - name: main
      image: alpine:3.20
      command: ["sh", "-c", "sleep 3600"]
YAML

kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" rollout status deployment/forbidden-endpoint --timeout=180s \
  > "$OUT_DIR/stdout/forbidden-rollout.out" 2> "$OUT_DIR/stderr/forbidden-rollout.err"
kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" wait --for=condition=Ready pod/tetragon-workload --timeout=180s \
  > "$OUT_DIR/stdout/tetragon-workload-ready.out" 2> "$OUT_DIR/stderr/tetragon-workload-ready.err"
kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" get pods -o wide > "$OUT_DIR/raw-data/tetragon-workload-pods.txt"
FORBIDDEN_IP="$(kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" get svc forbidden-svc -o jsonpath='{.spec.clusterIP}')"
echo "$FORBIDDEN_IP" > "$OUT_DIR/raw-data/forbidden-service-ip.txt"
WORKER_TETRAGON_POD="$(kubectl --context "$KUBE_CONTEXT" -n "$TETRAGON_NAMESPACE" get pods -l app.kubernetes.io/name=tetragon -o wide --no-headers | awk -v n="$NODE_NAME" '$7==n {print $1; exit}')"
if [[ -z "$WORKER_TETRAGON_POD" ]]; then
  echo "failed to resolve Tetragon pod on $NODE_NAME" >&2
  exit 1
fi
echo "$WORKER_TETRAGON_POD" > "$OUT_DIR/raw-data/worker-tetragon-pod.txt"

echo "triggering comparable runtime workload cases..."
(kubectl --context "$KUBE_CONTEXT" -n "$TETRAGON_NAMESPACE" exec "$WORKER_TETRAGON_POD" -c tetragon -- \
  sh -c "timeout 35s tetra getevents -o json --policy-names article2-baseline-comparison" \
  | grep "$FORBIDDEN_IP" \
  > "$TETRAGON_NETWORK_EVENTS_JSONL") \
  2> "$OUT_DIR/stderr/tetragon-tetra-network-events-filtered.err" &
NETWORK_COLLECTOR_PID=$!

sleep 8
: > "$OUT_DIR/stdout/tetragon-trigger-exec.out"
: > "$OUT_DIR/stderr/tetragon-trigger-exec.err"
for repetition_number in $(seq 1 5); do
  kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" exec pod/tetragon-workload -- /bin/ls / \
    >> "$OUT_DIR/stdout/tetragon-trigger-exec.out" 2>> "$OUT_DIR/stderr/tetragon-trigger-exec.err"
  echo "exec_repetition=$repetition_number" >> "$OUT_DIR/stdout/tetragon-trigger-exec.out"
  sleep 1
done
: > "$OUT_DIR/stdout/tetragon-trigger-connect.out"
: > "$OUT_DIR/stderr/tetragon-trigger-connect.err"
for repetition_number in $(seq 1 5); do
  kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" exec pod/tetragon-workload -- sh -c "wget -T 5 -q -O /dev/null http://$FORBIDDEN_IP/" \
    >> "$OUT_DIR/stdout/tetragon-trigger-connect.out" 2>> "$OUT_DIR/stderr/tetragon-trigger-connect.err"
  echo "connect_repetition=$repetition_number" >> "$OUT_DIR/stdout/tetragon-trigger-connect.out"
  sleep 1
done

set +e
wait "$NETWORK_COLLECTOR_PID"
NETWORK_COLLECTOR_EXIT=$?
set -e
echo "$NETWORK_COLLECTOR_EXIT" > "$OUT_DIR/raw-data/tetragon-tetra-network-events-filtered-exit-code.txt"

sleep 20
# --tail=-1 is required: kubectl logs -l defaults to a 10-line-per-pod tail
# when no --tail is given, which with 2 Tetragon pods (one per node) silently
# truncates to the last 20 lines total -- confirmed directly against this
# cluster (got exactly 20 lines, all unrelated agent-pod tcp_sendmsg noise,
# missing every actual workload trigger event). Same root cause as the
# equivalent fix in experiments/metrics/measure_revocation.sh.
kubectl --context "$KUBE_CONTEXT" -n "$TETRAGON_NAMESPACE" logs -l app.kubernetes.io/name=tetragon -c export-stdout --since=10m --tail=-1 \
  > "$TETRAGON_EVENTS_JSONL" 2> "$OUT_DIR/stderr/tetragon-events.err"

python3 - "$TETRAGON_EVENTS_JSONL" "$TETRAGON_NETWORK_EVENTS_JSONL" "$SUMMARY_CSV" "$FORBIDDEN_IP" "$WORKLOAD_NAMESPACE" <<'PY'
import csv, sys
process_events_path, network_events_path, summary_path, forbidden_ip, workload_namespace = sys.argv[1:6]
with open(process_events_path, errors="replace") as f:
    process_events = f.read()
with open(network_events_path, errors="replace") as f:
    network_events = f.read()

process_exec_count = process_events.count("process_exec")
exec_ls_count = process_events.count("/bin/ls")
connect_process_count = process_events.count("/usr/bin/wget")
connect_target_count = process_events.count(forbidden_ip)
namespace_count = process_events.count(workload_namespace)

# network_events (the separate live `tetra getevents --policy-names ...`
# collector) is best-effort and has been observed to exit non-zero on this
# Tetragon chart version -- primary source is process_events (the
# export-stdout log stream, already proven to carry tcp_connect/tcp_sendmsg/
# tcp_close kprobe events), scoped to lines that are actually the workload's
# own traffic to the forbidden IP (both tokens on the same line), not just
# "these substrings appear somewhere in the whole file".
workload_tcp_lines = [
    line for line in process_events.splitlines()
    if forbidden_ip in line and workload_namespace in line
    and ("tcp_connect" in line or "tcp_sendmsg" in line or "tcp_close" in line)
]
network_kprobe_count = network_events.count("process_kprobe") + sum(
    line.count("process_kprobe") for line in workload_tcp_lines
)
network_target_count = network_events.count(forbidden_ip) + len(workload_tcp_lines)
network_tcp_count = (
    network_events.count("tcp_connect") + network_events.count("tcp_sendmsg") + network_events.count("tcp_close")
    + sum(line.count("tcp_connect") + line.count("tcp_sendmsg") + line.count("tcp_close") for line in workload_tcp_lines)
)

rows = [
    ["tetragon", "A1-exec", "exec workload trigger attempted; raw process_exec attribution where exported",
     f"process_exec={process_exec_count};ls_tokens={exec_ls_count};namespace_tokens={namespace_count}",
     "PASS" if process_exec_count > 0 and exec_ls_count > 0 and namespace_count > 0 else "OBSERVED_LIMITATION",
     "raw-data/tetragon-events.jsonl"],
    ["tetragon", "A3-connect", "raw process_exec plus tcp kprobe event for forbidden service",
     f"wget_exec={connect_process_count};process_target_tokens={connect_target_count};network_kprobes={network_kprobe_count};network_tcp_tokens={network_tcp_count};network_target_tokens={network_target_count};forbidden_ip={forbidden_ip}",
     "PASS" if connect_process_count > 0 and connect_target_count > 0 and network_kprobe_count > 0 and network_target_count > 0 else "FAIL",
     "raw-data/tetragon-events.jsonl;raw-data/tetragon-tetra-network-events-filtered.jsonl"],
    ["tetragon", "A2-file-open", "equivalent file-open policy where locally safe",
     "not_executed_fd_install_unscoped_oom_risk_documented", "NOT_APPLICABLE",
     "deploy/kind/tetragon-baseline-policy.yaml"],
]

with open(summary_path, "a", newline="") as f:
    csv.writer(f, lineterminator="\n").writerows(rows)
PY

kubectl --context "$KUBE_CONTEXT" -n "$TETRAGON_NAMESPACE" get pods -o yaml > "$OUT_DIR/raw-data/tetragon-pods-final.yaml"
kubectl --context "$KUBE_CONTEXT" -n "$WORKLOAD_NAMESPACE" get all -o wide > "$OUT_DIR/raw-data/tetragon-workload-final.txt"
kubectl --context "$KUBE_CONTEXT" get tracingpolicy article2-baseline-comparison -o yaml > "$OUT_DIR/raw-data/tetragon-policy-final.yaml"

echo "summary written to $SUMMARY_CSV"
