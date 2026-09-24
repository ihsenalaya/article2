#!/usr/bin/env bash
# End-to-end LLM inference overhead benchmark: real tokens/s and latency
# (p50/p95/p99) for llm-inference-real, with vs without the eBPF agent
# attached. This is the headline number Phase 9-ter exists to produce --
# every other measurement this mission (propagation, revocation, per-hook
# latency) is a proxy for "does the agent cost anything," this is the direct
# answer for a real workload.
#
# Methodology: fixed prompt set + fixed seed/params in both conditions,
# warmup runs excluded from measurement, n >= 10 per condition. Removing
# the agent means deleting the DaemonSet entirely (not just the policy) so
# the "without agent" condition has zero eBPF programs attached at all --
# a true baseline, not just an unenforced policy.
#
# Usage: ./benchmark_llm_overhead.sh <service-url> <repetitions> <output-dir>
set -uo pipefail

SERVICE_URL="${1:?service URL required, e.g. http://20.x.x.x:8000}"
REPETITIONS="${2:-10}"
OUTPUT_DIR="${3:?output directory required}"
KUBE_CONTEXT="${KUBE_CONTEXT:-cgpu-vm}"

mkdir -p "$OUTPUT_DIR"

PROMPTS_FILE="$(dirname "${BASH_SOURCE[0]}")/benchmark_prompts.json"
if [ ! -f "$PROMPTS_FILE" ]; then
  cat > "$PROMPTS_FILE" <<'EOF'
[
  "Explain the difference between TCP and UDP in three sentences.",
  "Write a short Python function that computes the Fibonacci sequence.",
  "Summarize the plot of a typical hero's journey story in 100 words.",
  "What are the main differences between confidential computing and standard virtualization?",
  "List five best practices for securing a Kubernetes cluster."
]
EOF
fi

run_condition() {
  local condition="$1" out_csv="$2"
  echo "condition,repetition,prompt_index,tokens_generated,latency_seconds,tokens_per_second" > "$out_csv"

  echo "  warmup (not measured)..."
  python3 - "$SERVICE_URL" "$PROMPTS_FILE" <<'PYEOF' >/dev/null 2>&1
import json, sys, urllib.request
url, prompts_file = sys.argv[1], sys.argv[2]
prompts = json.load(open(prompts_file))
req = urllib.request.Request(f"{url}/v1/completions", data=json.dumps({
    "model": "llm-inference-real", "prompt": prompts[0], "max_tokens": 32, "temperature": 0, "seed": 42
}).encode(), headers={"Content-Type": "application/json"})
urllib.request.urlopen(req, timeout=60).read()
PYEOF

  for rep in $(seq 1 "$REPETITIONS"); do
    idx=$(( (rep - 1) % 5 ))
    prompt=$(python3 -c "import json; print(json.load(open('$PROMPTS_FILE'))[$idx])")
    result=$(python3 - "$SERVICE_URL" "$prompt" <<'PYEOF'
import json, sys, time, urllib.request
url, prompt = sys.argv[1], sys.argv[2]
body = json.dumps({
    "model": "llm-inference-real", "prompt": prompt, "max_tokens": 256,
    "temperature": 0, "seed": 42
}).encode()
req = urllib.request.Request(f"{url}/v1/completions", data=body, headers={"Content-Type": "application/json"})
t0 = time.time()
resp = json.loads(urllib.request.urlopen(req, timeout=120).read())
latency = time.time() - t0
tokens = resp.get("usage", {}).get("completion_tokens", 0)
print(f"{tokens},{latency},{tokens/latency if latency > 0 else 0}")
PYEOF
)
    echo "$condition,$rep,$idx,$result" >> "$out_csv"
    echo "  rep $rep: $result"
  done
}

echo "=== condition: with agent ==="
run_condition "with_agent" "$OUTPUT_DIR/benchmark_with_agent.csv"

echo "=== removing agent DaemonSet entirely for true baseline ==="
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-agent-system delete daemonset runtime-guard-agent --ignore-not-found
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-agent-system wait --for=delete pod -l app=runtime-guard-agent --timeout=60s 2>/dev/null || true
sleep 3

echo "=== condition: without agent (baseline) ==="
run_condition "without_agent" "$OUTPUT_DIR/benchmark_without_agent.csv"

echo "=== restoring agent DaemonSet ==="
kubectl --context "$KUBE_CONTEXT" apply -f "$(dirname "${BASH_SOURCE[0]}")/../../deploy/azure/cgpu-vm/agent-daemonset-cgpu-vm.yaml"
kubectl --context "$KUBE_CONTEXT" -n runtime-guard-agent-system rollout status daemonset/runtime-guard-agent --timeout=60s

echo "Raw results in $OUTPUT_DIR/benchmark_with_agent.csv and benchmark_without_agent.csv"
