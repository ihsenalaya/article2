#!/usr/bin/env bash
# Control-plane tampering experiment (Task 11): valid D + correct P (n
# reps, expect ACCEPTED) and valid D + tampered P (n reps, expect
# REJECTED with a fallback deny-all plan applied at the kernel level).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/results.jsonl"
: > "$OUT"

N=5

echo "=== condition: valid D + correct P (expect ACCEPTED) ==="
for rep in $(seq 1 "$N"); do
  pod_name="cpt-correct-rep${rep}-$RANDOM"
  echo "[correct-P] rep=$rep pod=$pod_name"
  create_and_authorize "$pod_name" || { echo "  setup failed" >&2; cleanup_pod "$pod_name"; continue; }
  verdict="$(steady_state_verdict "$pod_name")"
  echo "  verdict=$verdict"
  python3 -c "
import json
print(json.dumps({'condition': 'valid_D_correct_P', 'rep': $rep, 'pod': '$pod_name', 'verdict': '$verdict', 'expected': 'ACCEPTED'}))
" >> "$OUT"
  cleanup_pod "$pod_name"
  sleep 2
done

echo "=== condition: valid D + tampered P (expect REJECTED) ==="
for rep in $(seq 1 "$N"); do
  pod_name="cpt-tampered-rep${rep}-$RANDOM"
  echo "[tampered-P] rep=$rep pod=$pod_name"
  create_and_authorize "$pod_name" || { echo "  setup failed" >&2; cleanup_pod "$pod_name"; continue; }
  # Let it reach a stable ACCEPTED state first (confirms the baseline
  # really was trusted before tampering, not merely never-checked).
  baseline="$(steady_state_verdict "$pod_name")"
  echo "  baseline_verdict=$baseline"
  # Tamper: add a rogue AllowedPaths entry not authorized by D.
  kubectl -n workloads patch runtimesecuritypolicy "$pod_name" --type=merge \
    -p '{"spec":{"exec":{"defaultAction":"deny","allowedPaths":["/bin/sh"]}}}' >/dev/null 2>&1
  verdict="$(steady_state_verdict "$pod_name")"
  echo "  post_tamper_verdict=$verdict"
  python3 -c "
import json
print(json.dumps({'condition': 'valid_D_tampered_P', 'rep': $rep, 'pod': '$pod_name', 'baseline_verdict': '$baseline', 'verdict': '$verdict', 'expected': 'REJECTED'}))
" >> "$OUT"
  cleanup_pod "$pod_name"
  sleep 2
done

echo "done, $(wc -l < "$OUT") records in $OUT"
