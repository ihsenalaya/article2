#!/usr/bin/env bash
# C2: polling vs. watch-based revocation detection. Holds --poll-interval
# fixed at a deliberately slow 10s (so a watch-based improvement, if any,
# is clearly visible against that baseline) and toggles the agent's opt-in
# --watch-revocation path, measuring Delta_detect the same way as C1's
# fast loop. "Do not assume watch is faster; measure it" (experiment protocol).
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/c2-watch-vs-poll.jsonl"
: > "$OUT"

POLL_INTERVAL_FIXED=10s
REPS=10

run_condition() {
  local watch_enabled="$1" label="$2"
  echo "[c2] condition: watch_revocation=$watch_enabled (poll-interval fixed at $POLL_INTERVAL_FIXED)"
  set_poll_interval "$POLL_INTERVAL_FIXED"
  set_watch_revocation "$watch_enabled"

  local pod_name="c2-${label}"
  create_longrunning_pod "$pod_name" || { echo "[c2] setup failed for $pod_name" >&2; return; }

  declare -a T0S=()
  local version=0
  version=$((version + 1))
  mint_and_authorize "$pod_name" "$version" || { echo "[c2] initial auth failed" >&2; cleanup_pod "$pod_name"; return; }
  sleep 1

  for rep in $(seq 1 "$REPS"); do
    T0="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ | sed -E 's/([0-9]{6})[0-9]{3}Z$/\1Z/')"
    kubectl -n "$NS" delete aiplacementdecision "$pod_name" >/dev/null 2>&1
    T0S+=("$T0")
    echo "[c2]   $label rep $rep: revoked at t0=$T0"
    # Watch reacts near-instantly if enabled; poll is fixed at 10s. 15s
    # margin covers the slow (poll-only) condition comfortably.
    sleep 15
    version=$((version + 1))
    mint_and_authorize "$pod_name" "$version" >/dev/null 2>&1 || echo "[c2]   $label rep $rep: reauthorize failed" >&2
    sleep 1
  done

  echo "[c2] capturing agent logs for $pod_name..."
  RAW_LOG="$(mktemp)"
  kubectl -n "$AGENT_NS" logs -l app=runtime-guard-agent --since=8m --tail=-1 > "$RAW_LOG" 2>/dev/null

  for idx in "${!T0S[@]}"; do
    rep=$((idx + 1))
    T0="${T0S[$idx]}"
    LINE="$(awk -v t0="$T0" -v pol="policy=$NS/$pod_name" '
      /revoked access/ && index($0, pol) {
        split($1, a, "="); ts = a[2];
        if (ts > t0) { print; exit }
      }' "$RAW_LOG")"
    T1="" VIA=""
    if [ -n "$LINE" ]; then
      T1="$(echo "$LINE" | grep -oE '^time=[0-9T:.-]+Z' | sed 's/^time=//' | head -1)"
      VIA="$(echo "$LINE" | grep -oE 'via=[a-z]+' | sed 's/via=//' | head -1)"
    fi
    python3 -c "
import json, datetime
t0 = '$T0'
t1 = '$T1'
rec = {'condition': '$label', 'watch_revocation': $([ "$watch_enabled" = "true" ] && echo True || echo False),
       'poll_interval': '$POLL_INTERVAL_FIXED', 'rep': $rep, 't_rev': t0, 't_seen': t1 or None,
       'detected_via': '$VIA' or None, 'git_commit': '$GIT_SHA'}
if t1:
    d0 = datetime.datetime.strptime(t0, '%Y-%m-%dT%H:%M:%S.%fZ')
    d1 = datetime.datetime.strptime(t1, '%Y-%m-%dT%H:%M:%S.%fZ')
    rec['delta_detect_seconds'] = (d1 - d0).total_seconds()
    rec['outcome'] = 'success'
else:
    rec['delta_detect_seconds'] = None
    rec['outcome'] = 'not_found_in_log_window'
print(json.dumps(rec))
" >> "$OUT"
  done
  rm -f "$RAW_LOG"
  cleanup_pod "$pod_name"
}

run_condition false poll-only
run_condition true watch-enabled

# Restore watch-revocation to the production default (disabled) so later
# tasks/experiments in this campaign are unaffected by C2's toggle.
set_watch_revocation false

echo "[c2] done. $(wc -l < "$OUT") records"
