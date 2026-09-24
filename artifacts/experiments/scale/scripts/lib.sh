#!/usr/bin/env bash
# Shared helpers for Experiment E (Task 08, scalability).
set -uo pipefail

REPO_ROOT="${REPO_ROOT:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"
export KUBECONFIG="${KUBECONFIG:-$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/kubeconfig}"
TRUST_ANCHOR_ENV="$REPO_ROOT/deploy/azure/cpu-campaign-20260813/.run/secrets/trust-anchor.env"
GIT_SHA="$(git -C "$REPO_ROOT" rev-parse HEAD)"
NS=workloads
GENERATOR_IMAGE="acrarticle2ebpftm2ogg.azurecr.io/scale-generator:task08-qpsfix"
NODE_NAME="vm-a2-cpucampaign-20260813-worker"

source "$TRUST_ANCHOR_ENV"

# run_scale_job <n> <concurrency> <run_id> <converge_timeout> -- creates a
# Job running scale-generator with the given parameters, waits for it to
# complete, captures its stdout (one JSON object) to
# raw/<run_id>.json, then cleans up all pods/decisions/policies labeled
# scale-run=<run_id> plus the Job itself. Prints the path to the captured
# output on success, or "FAILED" on failure.
run_scale_job() {
  local n="$1" concurrency="$2" run_id="$3" converge_timeout="${4:-5m}"
  local job_name="scale-job-${run_id}"

  kubectl -n "$NS" delete job "$job_name" --wait=false --ignore-not-found >/dev/null 2>&1

  kubectl apply -f - >/dev/null <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: $job_name
  namespace: $NS
  labels: { experiment: scale, scale-run: "$run_id" }
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 600
  template:
    metadata:
      labels: { experiment: scale, scale-run: "$run_id" }
    spec:
      serviceAccountName: scale-generator
      restartPolicy: Never
      imagePullSecrets:
        - name: acr-pull-secret
      containers:
        - name: generator
          image: $GENERATOR_IMAGE
          imagePullPolicy: Always
          args:
            - --n=$n
            - --concurrency=$concurrency
            - --namespace=$NS
            - --node-name=$NODE_NAME
            - --run-id=$run_id
            - --priv-key-hex=$PRIVATE_KEY_HEX
            - --converge-timeout=$converge_timeout
            - --metrics-interval=2s
EOF

  local phase=""
  local waited=0
  while [ "$waited" -lt 700 ]; do
    phase="$(kubectl -n "$NS" get job "$job_name" -o jsonpath='{.status.succeeded}' 2>/dev/null || true)"
    failed="$(kubectl -n "$NS" get job "$job_name" -o jsonpath='{.status.failed}' 2>/dev/null || true)"
    [ "$phase" = "1" ] && break
    if [ -n "$failed" ] && [ "$failed" -ge 1 ]; then
      # Diagnostic logs go to a dedicated file, never to this function's
      # stdout: callers capture stdout via $(...), and even a
      # correctly-ordered stderr redirect here would earlier tempt the
      # same class of bug (see the "with open('FAILED" incident this
      # comment replaces) if a future edit gets the fd order wrong again.
      kubectl -n "$NS" logs "job/$job_name" --tail=-1 > "$PWD/../raw/${run_id}.failed-job-logs.txt" 2>&1
      echo "FAILED"
      return 1
    fi
    sleep 3
    waited=$((waited + 3))
  done
  if [ "$phase" != "1" ]; then
    echo "FAILED"
    return 1
  fi

  local out_path="$PWD/../raw/${run_id}.json"
  local raw_path="${out_path}.rawlog"
  # Two independent failure modes observed at N>=50, both handled here:
  # (1) Job succeeded=1 can be observed slightly before the pod's log
  #     stream is fully flushed/retrievable via the API server, producing
  #     an empty/truncated capture -- retried with backoff below.
  # (2) The container runtime interleaves stdout+stderr into one combined
  #     log stream. At higher concurrency, client-go's own client-side
  #     throttling warning (klog, written to stderr) can appear in that
  #     stream alongside the generator's single JSON result line (written
  #     last, to stdout, right before exit). So the last line -- not the
  #     whole capture -- is taken as the JSON payload.
  local attempt=0
  while [ "$attempt" -lt 5 ]; do
    kubectl -n "$NS" logs "job/$job_name" --tail=-1 > "$raw_path" 2>/dev/null
    if [ -s "$raw_path" ]; then
      tail -n 1 "$raw_path" > "$out_path"
      if python3 -c "import json,sys; json.load(open('$out_path'))" >/dev/null 2>&1; then
        echo "$out_path"
        return 0
      fi
    fi
    attempt=$((attempt + 1))
    sleep 2
  done
  echo "FAILED"
  return 1
}

cleanup_scale_run() {
  local run_id="$1"
  kubectl -n "$NS" delete job "scale-job-${run_id}" --wait=false --ignore-not-found >/dev/null 2>&1
  # Wait for actual pod termination (not --wait=false) before returning.
  # The worker node has a hard 110-pod capacity; at N=100 a fixed short
  # cooldown between reps left the previous rep's pods still terminating
  # when the next rep submitted, causing real (cluster-side-evidenced,
  # "Too many pods") transient scheduling failures cross-contaminating the
  # next rep's measurement (see e1-n100-rep1's 85/100 result and
  # exclusions.md). Blocking here isolates each rep's condition.
  kubectl -n "$NS" delete pods,aiplacementdecisions -l "scale-run=${run_id}" --wait=true --timeout=120s --ignore-not-found >/dev/null 2>&1
}
