#!/usr/bin/env bash
# C1: parameterized polling. Measures Delta_detect (t_rev -> t_seen, i.e.
# time from AIPlacementDecision deletion to the agent's "revoked access"
# log line) across five --poll-interval conditions, and, at reduced n
# (see below), Delta_evidence (t_rev -> t_T, first evidence reflecting
# AuthorizationState=revoked).
#
# t_invalid is not separately instrumented: RevokeCgroup() (which flips
# enforcement) is called synchronously, in the same function, immediately
# before the "revoked access" log line (see
# ebpf-agent/cmd/agent/main.go revokeTrackedPolicyLocked) -- there is no
# I/O or scheduling point between them, so t_invalid == t_seen to within
# the log timestamp's own resolution. This is a property of the current
# implementation confirmed by code inspection, not an unchecked
# assumption; stated explicitly in summary.md rather than silently folded
# into Delta_detect.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

FAST_OUT="$PWD/../raw/c1-detect-latency.jsonl"
SLOW_OUT="$PWD/../raw/c1-evidence-latency.jsonl"
: > "$FAST_OUT"
: > "$SLOW_OUT"

POLL_INTERVALS=(0.5s 1s 2s 5s 10s)
FAST_REPS=8
SLOW_REPS=3

for interval in "${POLL_INTERVALS[@]}"; do
  echo "[c1] setting --poll-interval=$interval"
  set_poll_interval "$interval"

  pod_name="c1-fast-${interval//./-}"
  echo "[c1] fast loop (Delta_detect, n=$FAST_REPS) on $pod_name"
  create_longrunning_pod "$pod_name" || { echo "[c1] setup failed for $pod_name" >&2; continue; }

  declare -a T0S=()
  version=0
  version=$((version + 1))
  mint_and_authorize "$pod_name" "$version" || { echo "[c1] initial auth failed" >&2; cleanup_pod "$pod_name"; continue; }
  sleep 1

  for rep in $(seq 1 "$FAST_REPS"); do
    T0="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ | sed -E 's/([0-9]{6})[0-9]{3}Z$/\1Z/')"
    kubectl -n "$NS" delete aiplacementdecision "$pod_name" >/dev/null 2>&1
    T0S+=("$T0")
    echo "[c1]   rep $rep: revoked at t0=$T0"
    # Wait long enough for even the slowest polling condition (10s) plus
    # margin to observe it before reauthorizing for the next rep.
    sleep 13
    version=$((version + 1))
    mint_and_authorize "$pod_name" "$version" >/dev/null 2>&1 || echo "[c1]   rep $rep: reauthorize failed" >&2
    sleep 1
  done

  echo "[c1] capturing agent logs for $pod_name..."
  RAW_LOG="$(mktemp)"
  kubectl -n "$AGENT_NS" logs -l app=runtime-guard-agent --since=5m --tail=-1 > "$RAW_LOG" 2>/dev/null

  for idx in "${!T0S[@]}"; do
    rep=$((idx + 1))
    T0="${T0S[$idx]}"
    LINE="$(awk -v t0="$T0" -v pol="policy=$NS/$pod_name" '
      /revoked access/ && index($0, pol) {
        split($1, a, "="); ts = a[2];
        if (ts > t0) { print; exit }
      }' "$RAW_LOG")"
    T1=""
    if [ -n "$LINE" ]; then
      T1="$(echo "$LINE" | grep -oE '^time=[0-9T:.-]+Z' | sed 's/^time=//' | head -1)"
    fi
    python3 -c "
import json, datetime
t0 = '$T0'
t1 = '$T1'
rec = {'poll_interval': '$interval', 'rep': $rep, 't_rev': t0, 't_seen': t1 or None, 'git_commit': '$GIT_SHA'}
if t1:
    d0 = datetime.datetime.strptime(t0, '%Y-%m-%dT%H:%M:%S.%fZ')
    d1 = datetime.datetime.strptime(t1, '%Y-%m-%dT%H:%M:%S.%fZ')
    rec['delta_detect_seconds'] = (d1 - d0).total_seconds()
    rec['outcome'] = 'success'
else:
    rec['delta_detect_seconds'] = None
    rec['outcome'] = 'not_found_in_log_window'
print(json.dumps(rec))
" >> "$FAST_OUT"
  done
  rm -f "$RAW_LOG"
  unset T0S
  cleanup_pod "$pod_name"

  # Slow loop, reduced n: also captures Delta_evidence (t_rev -> t_T, first
  # evidence with AuthorizationState=revoked), which needs a real wait for
  # an evidence tick (up to the fixed 30s evidence-interval) per rep, so is
  # kept at lower n as a documented scope decision -- see summary.md.
  pod_name="c1-slow-${interval//./-}"
  echo "[c1] slow loop (Delta_evidence, n=$SLOW_REPS) on $pod_name"
  create_longrunning_pod "$pod_name" || { echo "[c1] setup failed for $pod_name" >&2; continue; }
  version=0
  version=$((version + 1))
  mint_and_authorize "$pod_name" "$version" || { echo "[c1] initial auth failed" >&2; cleanup_pod "$pod_name"; continue; }
  sleep 1

  for rep in $(seq 1 "$SLOW_REPS"); do
    T0="$(date -u +%Y-%m-%dT%H:%M:%S.%NZ | sed -E 's/([0-9]{6})[0-9]{3}Z$/\1Z/')"
    t0_unix="$(date -u -d "$T0" +%s 2>/dev/null || python3 -c "import calendar,time; print(calendar.timegm(time.strptime('$T0'[:19], '%Y-%m-%dT%H:%M:%S')))")"
    kubectl -n "$NS" delete aiplacementdecision "$pod_name" >/dev/null 2>&1
    echo "[c1]   evidence rep $rep: revoked at t0=$T0"

    # Evidence is only refreshed on the fixed 30s global tick, so
    # AuthorizationState=revoked can still be TRUE UP TO 30s AFTER this
    # rep's own reauthorization already cleared it in a previous rep --
    # i.e. a stale leftover from an earlier revocation, not this rep's.
    # Require the evidence's own signed issuedAt to be strictly newer than
    # THIS rep's t0 before accepting it as this rep's t_T. A first version
    # of this loop accepted the first "revoked" reading unconditionally
    # and captured the exact same (~60-minute-stale) issuedAt on every
    # rep as a result -- caught because delta_evidence_seconds came out
    # deeply negative and identical across reps, which is not physically
    # possible for a value that should always be >= 0.
    auth_state="" issued_at_unix=""
    for _ in $(seq 1 40); do
      auth_state="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o jsonpath='{.status.authorizationState}' 2>/dev/null || true)"
      if [ "$auth_state" = "revoked" ]; then
        issued_at_str="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o jsonpath='{.status.signature.issuedAt}' 2>/dev/null || true)"
        if [ -n "$issued_at_str" ]; then
          # calendar.timegm (not datetime.strptime(...).timestamp(), which
          # silently interprets a naive/tz-less datetime as LOCAL time) --
          # this host's local timezone is Africa/Lagos (UTC+1), which
          # produced a systematic ~1-hour error the first time this ran,
          # making every candidate_unix compare as older than t0_unix even
          # when the real issuedAt was genuinely later. calendar.timegm
          # treats a struct_time as UTC unconditionally, matching the "Z"
          # suffix these Kubernetes timestamps always carry.
          candidate_unix="$(python3 -c "import calendar,time; print(calendar.timegm(time.strptime('$issued_at_str','%Y-%m-%dT%H:%M:%SZ')))" 2>/dev/null || echo 0)"
          if [ "$candidate_unix" -gt "$t0_unix" ]; then
            issued_at_unix="$candidate_unix"
            break
          fi
        fi
      fi
      sleep 1
    done
    python3 -c "
import json
rec = {'poll_interval': '$interval', 'rep': $rep, 't_rev_unix': $t0_unix, 'authorization_state': '$auth_state' or None,
       'git_commit': '$GIT_SHA'}
issued_unix = '$issued_at_unix'
if issued_unix:
    t_t = float(issued_unix)
    rec['t_T_unix'] = t_t
    rec['delta_evidence_seconds'] = t_t - $t0_unix
    rec['outcome'] = 'success'
else:
    rec['outcome'] = 'no_fresh_revoked_evidence_tick_in_window'
print(json.dumps(rec))
" >> "$SLOW_OUT"

    version=$((version + 1))
    mint_and_authorize "$pod_name" "$version" >/dev/null 2>&1 || echo "[c1]   evidence rep $rep: reauthorize failed" >&2
    sleep 1
  done
  cleanup_pod "$pod_name"
done

echo "[c1] done. $(wc -l < "$FAST_OUT") detect-latency records, $(wc -l < "$SLOW_OUT") evidence-latency records"
