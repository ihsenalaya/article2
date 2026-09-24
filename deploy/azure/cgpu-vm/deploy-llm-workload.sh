#!/usr/bin/env bash
# Deploys (or redeploys, for a config matrix -- see EXPERIMENTS_LOG.md Phase
# 9-quater) llm-inference-real with a configurable set of extra vLLM CLI
# args, mints its real allowlist decision, and waits for real readiness.
#
# Model weights are cached at a hostPath (/mnt/model-cache on the node), NOT
# an emptyDir: Phase 9-ter's emptyDir meant every pod recreation re-downloaded
# 15GB from HuggingFace (~1.5-2min each time). Testing a 4-5 config matrix
# with that cost would burn real GPU-billed minutes on redundant downloads --
# the init container now skips the download if the target dir already has the
# safetensors index file.
#
# Usage: ./deploy-llm-workload.sh [extra vLLM arg]...
#   e.g. ./deploy-llm-workload.sh --enforce-eager
#        ./deploy-llm-workload.sh --dtype=float16
#        VLLM_ATTENTION_BACKEND=FLASH_ATTN ./deploy-llm-workload.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CGPU_DIR="$REPO_ROOT/deploy/azure/cgpu-vm"
KUBE_CONTEXT="${KUBE_CONTEXT:-cgpu-vm}"
NAMESPACE="${NAMESPACE:-workloads}"
VLLM_ATTENTION_BACKEND="${VLLM_ATTENTION_BACKEND:-}"
VLLM_IMAGE="${VLLM_IMAGE:-vllm/vllm-openai:latest}"

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

# Build the extra-args YAML list from script args (each becomes its own
# "- \"...\"" line, appended after the fixed base args).
EXTRA_ARGS_YAML=""
for arg in "$@"; do
  EXTRA_ARGS_YAML="${EXTRA_ARGS_YAML}        - \"${arg}\"
"
done

ENV_YAML=""
if [ -n "$VLLM_ATTENTION_BACKEND" ]; then
  ENV_YAML="      env:
        - name: VLLM_ATTENTION_BACKEND
          value: \"${VLLM_ATTENTION_BACKEND}\"
"
fi

log "=== removing any existing llm-inference-real pod (redeploy for new config) ==="
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" delete pod llm-inference-real --ignore-not-found --grace-period=5
kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" delete aiplacementdecision llm-inference-real --ignore-not-found

log "=== applying pod: image=$VLLM_IMAGE args=[$*] attention_backend=${VLLM_ATTENTION_BACKEND:-<default>} ==="
cat <<EOF | kubectl --context "$KUBE_CONTEXT" apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: $NAMESPACE
---
apiVersion: v1
kind: Pod
metadata:
  name: llm-inference-real
  namespace: $NAMESPACE
  labels: { workload: llm-inference-real }
spec:
  runtimeClassName: nvidia
  imagePullSecrets:
    - name: acr-pull-secret
  initContainers:
    - name: fetch-model
      image: python:3.11-slim
      command: ["sh", "-c"]
      args:
        - |
          if [ -f /models/Qwen2.5-7B-Instruct/model.safetensors.index.json ]; then
            echo "model already cached at /models/Qwen2.5-7B-Instruct, skipping download"
          else
            pip install --no-cache-dir -q huggingface_hub
            python3 -c "
          from huggingface_hub import snapshot_download
          snapshot_download('Qwen/Qwen2.5-7B-Instruct', local_dir='/models/Qwen2.5-7B-Instruct')
          "
          fi
      volumeMounts:
        - name: models
          mountPath: /models
  containers:
    - name: vllm
      image: $VLLM_IMAGE
      command: ["python3", "-m", "vllm.entrypoints.openai.api_server"]
      args:
        - "--model=/models/Qwen2.5-7B-Instruct"
        - "--served-model-name=llm-inference-real"
        - "--port=8000"
        - "--gpu-memory-utilization=0.85"
        - "--max-model-len=4096"
${EXTRA_ARGS_YAML}${ENV_YAML}      ports:
        - containerPort: 8000
      resources:
        limits:
          nvidia.com/gpu: 1
      volumeMounts:
        - name: models
          mountPath: /models
          readOnly: true
      readinessProbe:
        httpGet:
          path: /health
          port: 8000
        initialDelaySeconds: 20
        periodSeconds: 5
        failureThreshold: 60
  volumes:
    - name: models
      hostPath:
        path: /mnt/model-cache
        type: DirectoryOrCreate
---
apiVersion: v1
kind: Service
metadata:
  name: llm-inference-real
  namespace: $NAMESPACE
spec:
  selector:
    workload: llm-inference-real
  ports:
    - port: 8000
      targetPort: 8000
EOF

log "=== waiting for real readiness (model download + vLLM startup) ==="
for i in $(seq 1 90); do
  ready=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod llm-inference-real -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null || true)
  phase=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod llm-inference-real -o jsonpath='{.status.phase}' 2>/dev/null || true)
  restarts=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod llm-inference-real -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)
  if [ "$ready" = "true" ]; then
    log "ready after ${i}x10s"
    break
  fi
  if [ "$phase" = "Failed" ] || [ "${restarts:-0}" -gt 2 ]; then
    log "GIVING UP: phase=$phase restarts=$restarts -- dumping logs"
    kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" logs llm-inference-real -c vllm --tail=50 2>&1 || true
    exit 1
  fi
  sleep 10
done
if [ "$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod llm-inference-real -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)" != "true" ]; then
  log "TIMEOUT waiting for readiness" >&2
  exit 1
fi

log "=== minting real allowlist decision ==="
POD_UID=$(kubectl --context "$KUBE_CONTEXT" -n "$NAMESPACE" get pod llm-inference-real -o jsonpath='{.metadata.uid}')
"$CGPU_DIR/mint-allowlist-decision.sh" llm-inference-real "$POD_UID"

log "=== done. Service reachable via: kubectl --context $KUBE_CONTEXT -n $NAMESPACE port-forward svc/llm-inference-real 8000:8000 ==="
