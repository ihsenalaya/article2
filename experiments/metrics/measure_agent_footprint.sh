#!/usr/bin/env bash
# Samples the node eBPF agent's own CPU/memory footprint via `crictl stats`
# on each node. Real, sampled data, not a single instantaneous reading —
# samples every INTERVAL seconds for DURATION seconds per node.
#
# Two node-access modes, since "how to run a command on the node" differs
# per environment (no metrics-server is installed in any of them, so this
# stays the direct containerd-level read throughout):
#   - kind (default): nodes are docker containers, `docker exec` works directly.
#   - ssh: for a real VM (Phase 9-bis confidential GPU VM) where nodes are
#     reached over SSH instead. Set ACCESS_MODE=ssh and SSH_TARGETS to a
#     space-separated list of user@host (one k3s node is typical, i.e. one
#     entry), SSH_KEY optionally.
#
# Usage: ./measure_agent_footprint.sh <duration_seconds> <interval_seconds> <output-csv>
# Env vars: NODES (docker mode, default kind's 2 nodes), ACCESS_MODE=kind|ssh,
#           SSH_TARGETS, SSH_KEY
set -uo pipefail

DURATION="${1:-60}"
INTERVAL="${2:-5}"
OUTPUT_CSV="${3:?output CSV path required}"
ACCESS_MODE="${ACCESS_MODE:-kind}"

if [ "$ACCESS_MODE" = "ssh" ]; then
  read -ra NODES <<< "${SSH_TARGETS:?set SSH_TARGETS to space-separated user@host entries for ACCESS_MODE=ssh}"
  SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_rsa}"
  run_on_node() { ssh -o StrictHostKeyChecking=accept-new -i "$SSH_KEY" "$1" "sudo k3s crictl stats -o json" 2>/dev/null; }
else
  read -ra NODES <<< "${NODES:-article2-control-plane article2-worker}"
  run_on_node() { docker exec "$1" crictl stats -o json 2>/dev/null; }
fi

echo "node,timestamp_ns,cpu_usage_nanocores,memory_working_set_bytes,memory_rss_bytes" > "$OUTPUT_CSV"

SAMPLES=$((DURATION / INTERVAL))
for i in $(seq 1 "$SAMPLES"); do
  for node in "${NODES[@]}"; do
    run_on_node "$node" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for s in d.get('stats', []):
    name = s.get('attributes', {}).get('metadata', {}).get('name', '')
    if name != 'agent':
        continue
    ts = s.get('cpu', {}).get('timestamp', '')
    cpu = s.get('cpu', {}).get('usageNanoCores', {}).get('value', '')
    mem_ws = s.get('memory', {}).get('workingSetBytes', {}).get('value', '')
    mem_rss = s.get('memory', {}).get('rssBytes', {}).get('value', '')
    print(f'$node,{ts},{cpu},{mem_ws},{mem_rss}')
" >> "$OUTPUT_CSV"
  done
  sleep "$INTERVAL"
done

echo "Raw samples written to $OUTPUT_CSV"
cat "$OUTPUT_CSV"
