#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
OUT_DIR="${TASK14_OUT_DIR:-$REPO_ROOT/results/tasks/TASK-14}"
if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$REPO_ROOT/$OUT_DIR"
fi

TF_DIR="$REPO_ROOT/deploy/azure/vm-k8s"
ACR_NAME="${ACR_NAME:-acrarticle2ebpftm2ogg}"
ACR_LOGIN_SERVER="${ACR_LOGIN_SERVER:-$ACR_NAME.azurecr.io}"
IMAGE_TAG="${IMAGE_TAG:-task14-$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)}"
KUBE_CONTEXT_NAME="${KUBE_CONTEXT_NAME:-article2-azure-vm-k8s}"
KUBECONFIG_PATH="$TF_DIR/.run/kubeconfig"
if [ -z "${SSH_KEY:-}" ]; then
  if [ -s "$OUT_DIR/raw-data/ssh-private-key-path.txt" ]; then
    SSH_KEY="$(cat "$OUT_DIR/raw-data/ssh-private-key-path.txt")"
  elif [ -s "$HOME/.ssh/article2_task13_ed25519" ]; then
    SSH_KEY="$HOME/.ssh/article2_task13_ed25519"
  else
    SSH_KEY="$HOME/.ssh/id_ed25519"
  fi
fi
PRELOAD_DIR="${TASK14_PRELOAD_DIR:-$TF_DIR/.run/task14-image-preload}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/kind/trust-anchor.env"
SUMMARY="$OUT_DIR/raw-data/azure-cpu-campaign-summary.csv"

mkdir -p "$OUT_DIR/raw-data" "$OUT_DIR/stdout" "$OUT_DIR/stderr" "$OUT_DIR/yaml" "$OUT_DIR/subruns"
printf '%s\n' "$SSH_KEY" > "$OUT_DIR/raw-data/ssh-private-key-path.txt"
echo "case,expected,actual,result,raw_artifact" > "$SUMMARY"

record() {
  local case_name="$1"
  local expected="$2"
  local actual="$3"
  local result="$4"
  local artifact="$5"
  printf '%s,"%s","%s",%s,%s\n' "$case_name" "$expected" "$actual" "$result" "$artifact" >> "$SUMMARY"
  echo "$case_name result=$result actual=$actual"
  [[ "$result" = "PASS" ]]
}

run_logged() {
  local name="$1"
  shift
  set +e
  "$@" > "$OUT_DIR/stdout/$name.out" 2> "$OUT_DIR/stderr/$name.err"
  local status=$?
  set -e
  echo "$status" > "$OUT_DIR/raw-data/$name.exit-code"
  return "$status"
}

cleanup() {
  set +e
  terraform -chdir="$TF_DIR" destroy -auto-approve > "$OUT_DIR/stdout/terraform-destroy.out" 2> "$OUT_DIR/stderr/terraform-destroy.err"
  echo "$?" > "$OUT_DIR/raw-data/terraform-destroy.exit-code"
  az group exists --name rg-a2-vmk8s-20260808 > "$OUT_DIR/raw-data/az-group-exists.post-destroy.txt" 2> "$OUT_DIR/stderr/az-group-exists.post-destroy.err"
}
trap cleanup EXIT

preload_images() {
  local output_json="$OUT_DIR/raw-data/terraform-output.json"
  local control_plane_ip worker_ip
  control_plane_ip="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["control_plane_public_ip"]["value"])' "$output_json")"
  worker_ip="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["worker_public_ip"]["value"])' "$output_json")"

  mkdir -p "$PRELOAD_DIR"
  docker save "$ACR_LOGIN_SERVER/runtime-guard-operator:$IMAGE_TAG" -o "$PRELOAD_DIR/operator.tar"
  docker save "$ACR_LOGIN_SERVER/runtime-guard-ebpf-agent:$IMAGE_TAG" -o "$PRELOAD_DIR/agent.tar"

  for entry in "control-plane:$control_plane_ip" "worker:$worker_ip"; do
    local role="${entry%%:*}"
    local ip="${entry#*:}"
    scp -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -i "$SSH_KEY" \
      "$PRELOAD_DIR/operator.tar" "$PRELOAD_DIR/agent.tar" "azureuser@$ip:/tmp/" \
      > "$OUT_DIR/stdout/scp-images-$role.out" 2> "$OUT_DIR/stderr/scp-images-$role.err"
    ssh -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=15 -o ConnectTimeout=10 -i "$SSH_KEY" "azureuser@$ip" \
      "sudo ctr -n k8s.io images import /tmp/operator.tar &&
       sudo ctr -n k8s.io images import /tmp/agent.tar &&
       sudo ctr -n k8s.io images ls | grep runtime-guard" \
      > "$OUT_DIR/stdout/ctr-import-images-$role.out" 2> "$OUT_DIR/stderr/ctr-import-images-$role.err"
  done
}

collect_cluster_diagnostics() {
  if [ -f "$KUBECONFIG_PATH" ]; then
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --context "$KUBE_CONTEXT_NAME" get nodes -o wide \
      > "$OUT_DIR/raw-data/diagnostic-nodes.txt" 2> "$OUT_DIR/stderr/diagnostic-nodes.err" || true
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --context "$KUBE_CONTEXT_NAME" get pods -A -o wide \
      > "$OUT_DIR/raw-data/diagnostic-pods.txt" 2> "$OUT_DIR/stderr/diagnostic-pods.err" || true
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --context "$KUBE_CONTEXT_NAME" get events -A --sort-by=.lastTimestamp \
      > "$OUT_DIR/raw-data/diagnostic-events.txt" 2> "$OUT_DIR/stderr/diagnostic-events.err" || true
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --context "$KUBE_CONTEXT_NAME" get aiplacementdecisions,runtimesecuritypolicies,runtimeplacementevidences -A -o yaml \
      > "$OUT_DIR/raw-data/diagnostic-runtime-objects.yaml" 2> "$OUT_DIR/stderr/diagnostic-runtime-objects.err" || true
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system logs daemonset/runtime-guard-agent --tail=300 \
      > "$OUT_DIR/raw-data/diagnostic-runtime-guard-agent.log" 2> "$OUT_DIR/stderr/diagnostic-runtime-guard-agent-log.err" || true
    KUBECONFIG="$KUBECONFIG_PATH" kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system logs deployment/runtime-guard-operator-controller-manager --tail=300 \
      > "$OUT_DIR/raw-data/diagnostic-runtime-guard-operator.log" 2> "$OUT_DIR/stderr/diagnostic-runtime-guard-operator-log.err" || true
  fi
}

echo "=== 1/9: Azure account and quota ==="
az account show -o json > "$OUT_DIR/raw-data/az-account-show.json"
az vm list-usage --location eastus2 -o table > "$OUT_DIR/raw-data/az-quota-eastus2.txt"

echo "=== 2/9: build and push current images ==="
docker build -t "$ACR_LOGIN_SERVER/runtime-guard-operator:$IMAGE_TAG" "$REPO_ROOT/operator" > "$OUT_DIR/stdout/docker-build-operator.out" 2> "$OUT_DIR/stderr/docker-build-operator.err"
docker build -f "$REPO_ROOT/ebpf-agent/Dockerfile" -t "$ACR_LOGIN_SERVER/runtime-guard-ebpf-agent:$IMAGE_TAG" "$REPO_ROOT" > "$OUT_DIR/stdout/docker-build-agent.out" 2> "$OUT_DIR/stderr/docker-build-agent.err"
az acr login --name "$ACR_NAME" > "$OUT_DIR/stdout/az-acr-login.out" 2> "$OUT_DIR/stderr/az-acr-login.err"
docker push "$ACR_LOGIN_SERVER/runtime-guard-operator:$IMAGE_TAG" > "$OUT_DIR/stdout/docker-push-operator.out" 2> "$OUT_DIR/stderr/docker-push-operator.err"
docker push "$ACR_LOGIN_SERVER/runtime-guard-ebpf-agent:$IMAGE_TAG" > "$OUT_DIR/stdout/docker-push-agent.out" 2> "$OUT_DIR/stderr/docker-push-agent.err"
OPERATOR_DIGEST="$(az acr repository show --name "$ACR_NAME" --image "runtime-guard-operator:$IMAGE_TAG" --query digest -o tsv | tr -d '\r')"
AGENT_DIGEST="$(az acr repository show --name "$ACR_NAME" --image "runtime-guard-ebpf-agent:$IMAGE_TAG" --query digest -o tsv | tr -d '\r')"
OPERATOR_IMAGE="$ACR_LOGIN_SERVER/runtime-guard-operator@$OPERATOR_DIGEST"
AGENT_IMAGE="$ACR_LOGIN_SERVER/runtime-guard-ebpf-agent@$AGENT_DIGEST"
OPERATOR_TAG_IMAGE="$ACR_LOGIN_SERVER/runtime-guard-operator:$IMAGE_TAG"
AGENT_TAG_IMAGE="$ACR_LOGIN_SERVER/runtime-guard-ebpf-agent:$IMAGE_TAG"
{
  echo "operator_image=$OPERATOR_IMAGE"
  echo "agent_image=$AGENT_IMAGE"
  echo "operator_tag_image=$OPERATOR_TAG_IMAGE"
  echo "agent_tag_image=$AGENT_TAG_IMAGE"
} > "$OUT_DIR/raw-data/acr-image-digests.env"

echo "=== 3/9: recreate Azure VM Kubernetes cluster ==="
terraform -chdir="$TF_DIR" plan -out task14.tfplan > "$OUT_DIR/stdout/terraform-plan.out" 2> "$OUT_DIR/stderr/terraform-plan.err"
terraform -chdir="$TF_DIR" apply -auto-approve task14.tfplan > "$OUT_DIR/stdout/terraform-apply.out" 2> "$OUT_DIR/stderr/terraform-apply.err"
terraform -chdir="$TF_DIR" output -json > "$OUT_DIR/raw-data/terraform-output.json"
SSH_KEY="$SSH_KEY" "$TF_DIR/scripts/bootstrap-cluster.sh" > "$OUT_DIR/stdout/bootstrap-cluster.out" 2> "$OUT_DIR/stderr/bootstrap-cluster.err"
OUT_DIR="$OUT_DIR/raw-data/cluster-validation" SSH_KEY="$SSH_KEY" "$TF_DIR/scripts/validate-cluster.sh" > "$OUT_DIR/stdout/validate-cluster.out" 2> "$OUT_DIR/stderr/validate-cluster.err"
preload_images

echo "=== 4/9: prepare manifests and pull secrets ==="
export KUBECONFIG="$KUBECONFIG_PATH"
kubectl --context "$KUBE_CONTEXT_NAME" create namespace runtime-guard-operator-system --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
kubectl --context "$KUBE_CONTEXT_NAME" create namespace runtime-guard-agent-system --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
kubectl --context "$KUBE_CONTEXT_NAME" create namespace workloads --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
ACR_TOKEN="$(az acr login --name "$ACR_NAME" --expose-token --output tsv --query accessToken)"
for namespace in runtime-guard-operator-system runtime-guard-agent-system workloads; do
  kubectl --context "$KUBE_CONTEXT_NAME" -n "$namespace" create secret docker-registry acr-pull-secret \
    --docker-server="$ACR_LOGIN_SERVER" \
    --docker-username="00000000-0000-0000-0000-000000000000" \
    --docker-password="$ACR_TOKEN" \
    --dry-run=client -o yaml | kubectl --context "$KUBE_CONTEXT_NAME" apply -f -
done

python3 - "$REPO_ROOT/deploy/azure/operator-manifests.yaml" "$OUT_DIR/yaml/operator-manifests-task14.yaml" "$OPERATOR_TAG_IMAGE" "$AGENT_IMAGE" <<'PY'
from pathlib import Path
import sys
src, dst, operator_image, agent_image = sys.argv[1:]
text = Path(src).read_text()
lines = []
for line in text.splitlines():
    stripped = line.strip()
    if stripped.startswith("image: acrarticle2ebpftm2ogg.azurecr.io/runtime-guard-operator:"):
        line = line[:line.index("image:")] + f"image: {operator_image}"
        lines.append(line)
        lines.append(line[:line.index("image:")] + "imagePullPolicy: Never")
        continue
    if stripped.startswith("- --agent-image-digest="):
        line = line[:line.index("- --agent-image-digest=")] + f"- --agent-image-digest={agent_image}"
    lines.append(line)
Path(dst).write_text("\n".join(lines) + "\n")
PY

python3 - "$REPO_ROOT/deploy/azure/agent-daemonset.yaml" "$OUT_DIR/yaml/agent-daemonset-task14.yaml" "$AGENT_TAG_IMAGE" <<'PY'
from pathlib import Path
import sys
src, dst, agent_image = sys.argv[1:]
text = Path(src).read_text()
lines = []
for line in text.splitlines():
    stripped = line.strip()
    if stripped.startswith("image: acrarticle2ebpftm2ogg.azurecr.io/runtime-guard-ebpf-agent:"):
        line = line[:line.index("image:")] + f"image: {agent_image}"
    if stripped.startswith("imagePullPolicy:"):
        line = line[:line.index("imagePullPolicy:")] + "imagePullPolicy: Never"
    if stripped.startswith("value: \"acrarticle2ebpftm2ogg.azurecr.io/runtime-guard-ebpf-agent@"):
        line = line[:line.index("value:")] + f"value: \"{agent_image}\""
    lines.append(line)
Path(dst).write_text("\n".join(lines) + "\n")
PY

echo "=== 5/9: deploy operator and agent ==="
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$REPO_ROOT/deploy/kind/upstream-aiplacementdecision-crd.yaml" > "$OUT_DIR/stdout/apply-upstream-crd.out" 2> "$OUT_DIR/stderr/apply-upstream-crd.err"
KUBE_CONTEXT="$KUBE_CONTEXT_NAME" "$REPO_ROOT/deploy/kind/gen-trust-anchor.sh" > "$OUT_DIR/stdout/gen-trust-anchor.out" 2> "$OUT_DIR/stderr/gen-trust-anchor.err"
KUBE_CONTEXT="$KUBE_CONTEXT_NAME" "$REPO_ROOT/deploy/kind/gen-agent-key.sh" > "$OUT_DIR/stdout/gen-agent-key.out" 2> "$OUT_DIR/stderr/gen-agent-key.err"
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$OUT_DIR/yaml/operator-manifests-task14.yaml" > "$OUT_DIR/stdout/apply-operator.out" 2> "$OUT_DIR/stderr/apply-operator.err"
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$OUT_DIR/yaml/agent-daemonset-task14.yaml" > "$OUT_DIR/stdout/apply-agent.out" 2> "$OUT_DIR/stderr/apply-agent.err"
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system patch serviceaccount runtime-guard-operator-controller-manager -p '{"imagePullSecrets":[{"name":"acr-pull-secret"}]}' >/dev/null
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system patch serviceaccount runtime-guard-agent -p '{"imagePullSecrets":[{"name":"acr-pull-secret"}]}' >/dev/null
# operator-manifests.yaml no longer hardcodes a (stale-prone) --agent-image-digest
# arg; the operator refuses to generate any RuntimeSecurityPolicy without one
# (see AIPlacementDecisionReconciler), so it must be injected at deploy time --
# same mechanism deploy/kind/create-lab.sh already uses for the kind path.
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system set env \
  deployment/runtime-guard-operator-controller-manager \
  "AGENT_IMAGE_DIGEST=$AGENT_IMAGE" > "$OUT_DIR/stdout/set-env-operator.out" 2> "$OUT_DIR/stderr/set-env-operator.err"
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system rollout restart deployment/runtime-guard-operator-controller-manager >/dev/null
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system rollout restart daemonset/runtime-guard-agent >/dev/null
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system rollout status deployment/runtime-guard-operator-controller-manager --timeout=180s > "$OUT_DIR/stdout/operator-rollout.out" 2> "$OUT_DIR/stderr/operator-rollout.err"
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system rollout status daemonset/runtime-guard-agent --timeout=180s > "$OUT_DIR/stdout/agent-rollout.out" 2> "$OUT_DIR/stderr/agent-rollout.err"
kubectl --context "$KUBE_CONTEXT_NAME" get pods -A -o wide > "$OUT_DIR/raw-data/pods-after-runtime-guard.txt"

echo "=== 6/9: run control-plane security experiments on Azure CPU ==="
if ! KUBE_CONTEXT="$KUBE_CONTEXT_NAME" TRUST_ANCHOR_ENV="$TRUST_ANCHOR_ENV" TASK04_NAMESPACE=task14-anti-replay \
  "$REPO_ROOT/experiments/attacks/task04-anti-replay-kind.sh" "$OUT_DIR/raw-data/task04-anti-replay-azure-cpu.csv" > "$OUT_DIR/stdout/task04-anti-replay.out" 2> "$OUT_DIR/stderr/task04-anti-replay.err"; then
  collect_cluster_diagnostics
  exit 1
fi
if ! KUBE_CONTEXT="$KUBE_CONTEXT_NAME" TRUST_ANCHOR_ENV="$TRUST_ANCHOR_ENV" TASK05_NAMESPACE=task14-deterministic \
  "$REPO_ROOT/experiments/attacks/task05-deterministic-policy-kind.sh" "$OUT_DIR/raw-data/task05-deterministic-policy-azure-cpu.csv" > "$OUT_DIR/stdout/task05-deterministic-policy.out" 2> "$OUT_DIR/stderr/task05-deterministic-policy.err"; then
  collect_cluster_diagnostics
  exit 1
fi

echo "=== 7/9: run Azure CPU workload/evidence probe ==="
cat > "$OUT_DIR/yaml/cpu-workload.yaml" <<'YAML'
apiVersion: v1
kind: Namespace
metadata:
  name: task14-azure-cpu
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: forbidden-endpoint
  namespace: task14-azure-cpu
spec:
  replicas: 1
  selector:
    matchLabels: { app: forbidden-endpoint }
  template:
    metadata:
      labels: { app: forbidden-endpoint }
    spec:
      containers:
        - name: nginx
          image: nginx:1.27-alpine
          ports: [{ containerPort: 80 }]
---
apiVersion: v1
kind: Service
metadata:
  name: forbidden-svc
  namespace: task14-azure-cpu
spec:
  selector:
    app: forbidden-endpoint
  ports:
    - port: 80
      targetPort: 80
---
apiVersion: v1
kind: Pod
metadata:
  name: azure-cpu-probe
  namespace: task14-azure-cpu
  labels: { workload: azure-cpu-probe }
spec:
  containers:
    - name: main
      image: alpine:3.20
      command: ["sh", "-c", "apk add --no-cache wget >/dev/null 2>&1; sleep 3600"]
YAML
kubectl --context "$KUBE_CONTEXT_NAME" apply -f "$OUT_DIR/yaml/cpu-workload.yaml" > "$OUT_DIR/stdout/apply-cpu-workload.out" 2> "$OUT_DIR/stderr/apply-cpu-workload.err"
kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu rollout status deployment/forbidden-endpoint --timeout=120s > "$OUT_DIR/stdout/forbidden-rollout.out" 2> "$OUT_DIR/stderr/forbidden-rollout.err"
kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu wait --for=condition=Ready pod/azure-cpu-probe --timeout=120s > "$OUT_DIR/stdout/probe-ready.out" 2> "$OUT_DIR/stderr/probe-ready.err"
POD_UID="$(kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get pod azure-cpu-probe -o jsonpath='{.metadata.uid}')"
NODE_NAME="$(kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get pod azure-cpu-probe -o jsonpath='{.spec.nodeName}')"
export TRUST_ANCHOR_PRIVATE_KEY_HEX
# shellcheck disable=SC1090
source "$TRUST_ANCHOR_ENV"
(cd "$REPO_ROOT/operator" && go run ./cmd/mint-test-decision \
  --name azure-cpu-probe \
  --namespace task14-azure-cpu \
  --target-name azure-cpu-probe \
  --pod-uid "$POD_UID" \
  --node-identity "$NODE_NAME" \
  --decision-id task14-azure-cpu-probe \
  --decision-version 1 \
  --decision-epoch 1 \
  --decision-nonce nonce-task14-azure-cpu) | kubectl --context "$KUBE_CONTEXT_NAME" apply -f - > "$OUT_DIR/stdout/apply-cpu-decision.out" 2> "$OUT_DIR/stderr/apply-cpu-decision.err"
kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu patch aiplacementdecision azure-cpu-probe --subresource=status --type=merge -p '{"status":{"decision":"allow"}}' > "$OUT_DIR/stdout/patch-cpu-decision-status.out" 2> "$OUT_DIR/stderr/patch-cpu-decision-status.err"

for _ in $(seq 1 120); do
  decision="$(kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get runtimesecuritypolicy azure-cpu-probe -o jsonpath='{.status.decision}' 2>/dev/null || true)"
  ready="$(kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get runtimesecuritypolicy azure-cpu-probe -o jsonpath='{.status.conditions[?(@.type=="EnforcementReady")].status}' 2>/dev/null || true)"
  if [ "$decision" = "active" ] && [ "$ready" = "True" ]; then
    break
  fi
  sleep 1
done
kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get runtimesecuritypolicy azure-cpu-probe -o yaml > "$OUT_DIR/raw-data/azure-cpu-runtimesecuritypolicy.yaml"

for _ in $(seq 1 5); do
  kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu exec azure-cpu-probe -- /bin/ls /tmp >/dev/null 2>> "$OUT_DIR/stderr/probe-exec-ls.err" || true
  kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu exec azure-cpu-probe -- wget -T 2 -q -O /dev/null http://forbidden-svc.task14-azure-cpu.svc.cluster.local/ >/dev/null 2>> "$OUT_DIR/stderr/probe-connect-forbidden.err" || true
done
sleep 20
kubectl --context "$KUBE_CONTEXT_NAME" get runtimeplacementevidence -A -o yaml > "$OUT_DIR/raw-data/runtimeplacementevidence-after-probes.yaml"
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-agent-system logs daemonset/runtime-guard-agent --tail=200 > "$OUT_DIR/raw-data/runtime-guard-agent.log" 2> "$OUT_DIR/stderr/runtime-guard-agent-log.err" || true
kubectl --context "$KUBE_CONTEXT_NAME" -n runtime-guard-operator-system logs deployment/runtime-guard-operator-controller-manager --tail=200 > "$OUT_DIR/raw-data/runtime-guard-operator.log" 2> "$OUT_DIR/stderr/runtime-guard-operator-log.err" || true

echo "=== 8/9: summarize results ==="
# task04's CSV is "case,expected,actual,reason,result" -- reason is free text
# and can itself contain a comma (e.g. "invalid ed25519 signature length: got
# 1, want 64"), which shifts a fixed $5 off the real result column. result is
# always the true last field (nothing follows it), so match on $NF instead.
task04_failures="$(awk -F, 'NR>1 && $NF!="PASS"{c++} END{print c+0}' "$OUT_DIR/raw-data/task04-anti-replay-azure-cpu.csv")"
task05_failures="$(awk -F, 'NR>1 && $4!="PASS"{c++} END{print c+0}' "$OUT_DIR/raw-data/task05-deterministic-policy-azure-cpu.csv")"
rsp_decision="$(kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get runtimesecuritypolicy azure-cpu-probe -o jsonpath='{.status.decision}' 2>/dev/null || true)"
rsp_ready="$(kubectl --context "$KUBE_CONTEXT_NAME" -n task14-azure-cpu get runtimesecuritypolicy azure-cpu-probe -o jsonpath='{.status.conditions[?(@.type=="EnforcementReady")].status}' 2>/dev/null || true)"
evidence_count="$(kubectl --context "$KUBE_CONTEXT_NAME" get runtimeplacementevidence -A --no-headers 2>/dev/null | wc -l | tr -d ' ')"
record task04-anti-replay "all anti-replay rows PASS on Azure CPU" "failures=$task04_failures" "$([ "$task04_failures" = 0 ] && echo PASS || echo FAIL)" raw-data/task04-anti-replay-azure-cpu.csv
record task05-deterministic-policy "all deterministic rows PASS on Azure CPU" "failures=$task05_failures" "$([ "$task05_failures" = 0 ] && echo PASS || echo FAIL)" raw-data/task05-deterministic-policy-azure-cpu.csv
record azure-cpu-policy-evidence "RuntimeSecurityPolicy active and EnforcementReady with evidence object" "decision=$rsp_decision ready=$rsp_ready evidence_count=$evidence_count" "$([ "$rsp_decision" = active ] && [ "$rsp_ready" = True ] && [ "$evidence_count" -gt 0 ] && echo PASS || echo FAIL)" raw-data/runtimeplacementevidence-after-probes.yaml

echo "=== 9/9: final cluster snapshot before destroy ==="
kubectl --context "$KUBE_CONTEXT_NAME" get nodes -o wide > "$OUT_DIR/raw-data/final-nodes.txt"
kubectl --context "$KUBE_CONTEXT_NAME" get pods -A -o wide > "$OUT_DIR/raw-data/final-pods.txt"

echo "summary written to $SUMMARY"
