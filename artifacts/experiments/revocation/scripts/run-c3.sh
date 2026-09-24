#!/usr/bin/env bash
# C3/Q7: can a cryptographically valid evidence object remain semantically
# stale with respect to authorization? Captures a real, signed evidence
# object emitted WHILE the pod is authorized and conform, then revokes the
# decision afterward, and checks that captured (now-stale) snapshot with
# verify-evidence twice: once with the Task 06 authorization-currency
# check disabled (--max-authorization-age=0, standing in for a verifier
# using only pre-Task-06 checks -- AuthorizationState/RevokedAt/
# LastAuthorizationSync did not exist as signed, checkable fields before
# this task) and once with it enabled (the default). The question this
# answers is specifically about a REPLAYED/cached evidence snapshot, not
# the live CR (which the agent keeps updating) -- exactly the scenario a
# verifier evaluating an evidence artifact out-of-band (e.g. from a log
# export, or a delayed audit pipeline) would face.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
source ./lib.sh

OUT="$PWD/../raw/c3-stale-evidence.jsonl"
: > "$OUT"
# Randomized, not a fixed literal: the anti-replay ledger
# (decision_ledger.go) is a persistent ConfigMap keyed by decision_id, not
# tied to the K8s object's own lifecycle -- reusing a fixed pod name
# across separate script invocations (e.g. rerunning this script after a
# fix) collides with a decision_id+version the ledger already recorded
# from a prior run, silently producing a REJECTED decision with empty
# Spec.Binding/Spec.Derivation (see lib.sh's mint_and_authorize, which now
# explicitly checks for and fails loudly on this).
pod_name="c3-stale-evidence-$RANDOM"

set_poll_interval 5s
set_watch_revocation false

echo "[c3] creating policy-bound workload: $pod_name"
create_longrunning_pod "$pod_name" || { echo "[c3] setup failed" >&2; exit 1; }
mint_and_authorize "$pod_name" 1 || { echo "[c3] initial auth failed" >&2; cleanup_pod "$pod_name"; exit 1; }

echo "[c3] waiting for a conform+authorized evidence emission..."
auth_state="" conformance=""
for _ in $(seq 1 40); do
  auth_state="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o jsonpath='{.status.authorizationState}' 2>/dev/null || true)"
  conformance="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o jsonpath='{.status.conformance}' 2>/dev/null || true)"
  [ "$auth_state" = "authorized" ] && [ "$conformance" = "conform" ] && break
  sleep 1
done
if [ "$auth_state" != "authorized" ] || [ "$conformance" != "conform" ]; then
  echo "[c3] never observed authorized+conform evidence (auth_state=$auth_state conformance=$conformance)" >&2
  cleanup_pod "$pod_name"
  exit 1
fi

captured_dir="$(mktemp -d)"
kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o yaml > "$captured_dir/pre-revocation-evidence.yaml"
kubectl -n "$NS" get runtimesecuritypolicy "$pod_name" -o yaml > "$captured_dir/policy.yaml"
# Also copy into verifier-output/ permanently (not just the temp dir, which
# is deleted at the end of this script) so the exact inputs behind the
# verify-evidence reports below are reproducible/inspectable afterward --
# not just their output reports.
cp "$captured_dir/pre-revocation-evidence.yaml" "$PWD/../verifier-output/c3-captured-pre-revocation-evidence.yaml"
cp "$captured_dir/policy.yaml" "$PWD/../verifier-output/c3-captured-policy.yaml"
captured_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[c3] captured pre-revocation evidence snapshot at $captured_at (authorizationState=authorized, conformance=conform)"

echo "[c3] revoking decision..."
kubectl -n "$NS" delete aiplacementdecision "$pod_name" >/dev/null 2>&1

wait_seconds=90
echo "[c3] waiting ${wait_seconds}s (well past detection + evidence-tick propagation) before checking the CAPTURED snapshot against wall-clock now..."
sleep "$wait_seconds"

# Confirm on the LIVE object that revocation really did propagate, as a
# sanity check that this isn't a vacuous "revocation never happened"
# result.
live_auth_state="$(kubectl -n "$EVIDENCE_NS" get runtimeplacementevidence "$pod_name" -o jsonpath='{.status.authorizationState}' 2>/dev/null || true)"
echo "[c3] live evidence object authorizationState is now: $live_auth_state"

echo "[c3] verifying the CAPTURED (stale) snapshot with authorization-currency DISABLED (--max-authorization-age=0, models a pre-Task-06 verifier)..."
report_disabled="$(cd "$REPO_ROOT/operator" && go run ./cmd/verify-evidence \
  --evidence-file "$captured_dir/pre-revocation-evidence.yaml" --policy-file "$captured_dir/policy.yaml" \
  --public-key-hex "$AGENT_PUB_KEY_HEX" --max-authorization-age 0 2>/dev/null)"
echo "$report_disabled" > "$PWD/../verifier-output/c3-stale-authcurrency-disabled.json"

echo "[c3] verifying the SAME captured (stale) snapshot with authorization-currency ENABLED (default 15s)..."
report_enabled="$(cd "$REPO_ROOT/operator" && go run ./cmd/verify-evidence \
  --evidence-file "$captured_dir/pre-revocation-evidence.yaml" --policy-file "$captured_dir/policy.yaml" \
  --public-key-hex "$AGENT_PUB_KEY_HEX" 2>/dev/null)"
echo "$report_enabled" > "$PWD/../verifier-output/c3-stale-authcurrency-enabled.json"

# Read the two verify-evidence reports from the files already written above
# rather than re-embedding their JSON text into a bash-substituted Python
# string literal: the reports' check messages contain escaped double quotes
# (e.g. algorithm=\"ed25519\"), and Python unescapes those INSIDE a
# triple-quoted string literal before json.loads ever sees the text --
# corrupting the JSON and breaking the parse. Reading the file directly
# sidesteps any shell<->Python text-embedding entirely.
python3 -c "
import json
with open('$PWD/../verifier-output/c3-stale-authcurrency-disabled.json') as f:
    disabled = json.load(f)
with open('$PWD/../verifier-output/c3-stale-authcurrency-enabled.json') as f:
    enabled = json.load(f)
rec = {
    'pod_name': '$pod_name',
    'captured_at': '$captured_at',
    'wait_seconds_before_check': $wait_seconds,
    'live_authorization_state_after_wait': '$live_auth_state' or None,
    'revocation_confirmed_live': '$live_auth_state' == 'revoked',
    'authcurrency_disabled': {
        'valid': disabled.get('valid'),
        'authorized_and_compliant': disabled.get('authorized_and_compliant'),
    },
    'authcurrency_enabled': {
        'valid': enabled.get('valid'),
        'authorized_and_compliant': enabled.get('authorized_and_compliant'),
    },
    'finding': 'a captured, correctly-signed, pre-revocation evidence snapshot is accepted as AuthorizedAndCompliant by a verifier without the authorization-currency check, and correctly rejected by one with it' if (disabled.get('authorized_and_compliant') and not enabled.get('authorized_and_compliant')) else 'UNEXPECTED: see raw verifier-output/ reports',
    'git_commit': '$GIT_SHA',
}
print(json.dumps(rec))
" >> "$OUT"

cleanup_pod "$pod_name"
rm -rf "$captured_dir"
echo "[c3] done, $(wc -l < "$OUT") records in $OUT"
