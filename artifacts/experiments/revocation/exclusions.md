# Exclusions and discarded runs — Experiment C (Task 06)

Per experiment protocol rule 21: failed/invalidated runs are never silently
deleted. This file records every discarded attempt from this task, why it
was discarded, and what it changed about the final methodology. Raw
discarded data is retained under `discarded-runs/` (not counted in any
reported statistic).

## C1 (parameterized polling): two discarded sweeps, two real bugs found and fixed

### Attempt 1 — `c1-detect-latency-PRE-STALE-EVIDENCE-FIX-discarded.jsonl` / `c1-evidence-latency-PRE-STALE-EVIDENCE-FIX-discarded.jsonl`

First full C1 attempt with the slow (evidence-latency) loop's initial
version. `c1-detect-latency.jsonl` from this attempt was fine (the fast
loop doesn't touch evidence timing at all); the paired
`c1-evidence-latency` file showed the stale-evidence-match bug described
below (two records with identical, ~60-minute-stale `t_T_unix` and deeply
negative `delta_evidence_seconds`, not physically possible).

### Attempt 2 — `c1-detect-latency-PRE-TZ-FIX-discarded.jsonl` / `c1-evidence-latency-PRE-TZ-FIX-discarded.jsonl`

After fixing the stale-evidence-match bug, rerun from scratch (the fast
loop's data is identical in shape/validity to attempt 1's, just
regenerated together with the slow loop for a clean paired run). The slow
loop's first two reps then hit the second bug (timezone), producing
`no_fresh_revoked_evidence_tick_in_window`/deeply-negative-delta outcomes
as described below.

Two distinct, sequential bugs were found and fixed across these two
attempts:

**Bug A — stale-evidence match**: the slow loop's first working version
accepted the *first* reading of `authorizationState=revoked` as this rep's
result. Since evidence only refreshes on the agent's fixed 30s global tick,
and reauthorization between reps does not immediately clear the *previous*
tick's stale "revoked" value, the loop was matching a **leftover reading
from an earlier revocation**, not the current rep's. Symptom: every rep
captured the exact same `t_T_unix` (~60 minutes stale) and
`delta_evidence_seconds` came out identical and deeply negative across all
three reps — not physically possible for a value that should always be
`>= 0`, which is what made this catchable rather than silently accepted.

**Fix**: require the evidence's own signed `issuedAt` to be strictly newer
than *this rep's* `t_rev` before accepting it (`run-c1.sh`'s slow loop).

**Bug B — timezone**: with the stale-match fix applied, delta values were
*still* wrong (deeply negative, ~-3494s instead of the true +106s gap).
Root cause: this host's local timezone is `Africa/Lagos` (UTC+1;
`timedatectl` confirmed), and Python's `datetime.datetime.strptime(...).timestamp()`
on a naive (tz-less) datetime silently interprets it as **local time**, not
UTC — even though the string being parsed (`...Z` suffix) unambiguously
denotes UTC. This produced a systematic ~1-hour error whenever mixed with a
genuinely-UTC-computed value (bash's `date -u -d ... +%s`, used for
`t0_unix`); it did not surface in Δ_detect's calculation because that one
computes a pure difference between two naive datetimes parsed the *same*
way, so the systematic error cancels out — it only surfaced here because
`t_t` (Python-parsed) and `t0_unix` (bash-`date -u`-parsed) were on
different, inconsistently-handled bases.

**Fix**: replaced `datetime.strptime(...).timestamp()` with
`calendar.timegm(time.strptime(...))`, which treats a parsed struct_time as
UTC unconditionally, matching what the `Z` suffix actually means.

### Final, retained run — `raw/c1-detect-latency.jsonl`, `raw/c1-evidence-latency.jsonl`

With both fixes applied, all 40 detect-latency reps (5 conditions × 8) and
all 15 evidence-latency reps (5 conditions × 3) succeeded with physically
sensible values (Δ_detect scaling cleanly with poll-interval; Δ_evidence
staying in a consistent ~11-29s band regardless of poll-interval, zero
`no_fresh_revoked_evidence_tick_in_window` outcomes on the retained run).

## C2 (watch vs. poll): one discarded attempt, one real bug found and fixed

### Discarded — no raw file exists; data was never written at all

First C2 attempt's poll-only condition (10 reps) and the first rep of the
watch-enabled condition ran live against the cluster (real revoke/
reauthorize cycles genuinely happened), but **every rep's summarization
step crashed silently** with `NameError: name 'false' is not defined`.

**Root cause**: the per-rep Python summarization block computed the
`watch_revocation` JSON field via a bash command substitution
(`$([ "$watch_enabled" = "true" ] && echo true || echo false)`) that
emitted the **lowercase** literal `true`/`false` directly into the Python
source text. Python has no bare `true`/`false` keyword (only capitalized
`True`/`False`), so every invocation raised a `NameError` before writing
anything to the output file — silently, since the script does not use
`set -e` and the crash's stderr output went to the terminal/log, not to a
place that would halt the sweep. This was caught by noticing the raw
output file was empty (0 records) after a run that had visibly executed
11 real revoke cycles against the cluster.

**Fix**: capitalized the echoed literals (`echo True || echo False`).
Verified in isolation before rerunning against the live cluster. No other
occurrence of this pattern existed in `run-c1.sh`/`run-c3.sh` (checked via
`grep -n "echo true\|echo false"` across all three scripts).

Since no raw data survived this attempt (the in-memory `T0S` array and
temp log file are local to the function and were gone once it returned),
this was a full loss requiring a complete rerun of both conditions, not a
partial-data situation — there is nothing to place under
`discarded-runs/` for this attempt because nothing was ever persisted.

### Final, retained run — `raw/c2-watch-vs-poll.jsonl`

All 20 reps (10 poll-only + 10 watch-enabled) succeeded. Every
watch-enabled rep's `detected_via` field reads `watch` (not `poll`),
confirming the watch path genuinely won the detection race every time
rather than poll coincidentally being fast.

## C3 (stale-evidence demonstration): two discarded attempts, two real bugs found and fixed

### Discarded attempt 1 — `c3-stale-authcurrency-{disabled,enabled}.json` (verifier-output files from the first attempt, still present; superseded by the retained run's files of the same name)

The live cluster operations (pod creation, evidence capture, revocation,
the 90s wait, and both `verify-evidence` invocations) all executed
correctly and produced genuine reports — but the final summarization step
crashed with `json.decoder.JSONDecodeError: Expecting ',' delimiter`,
producing 0 records in `raw/c3-stale-evidence.jsonl`.

**Root cause**: the two verify-evidence JSON reports were embedded into a
Python summarization script via bash triple-single-quote substitution
(`json.loads('''$report_disabled''')`). The reports' check messages contain
JSON-escaped double quotes (e.g. `"message": "algorithm=\"ed25519\""`).
When that literal text lands inside a Python triple-quoted string literal,
**Python's own string-literal parser unescapes `\"` to `"` before
`json.loads` ever runs** — turning valid JSON into invalid JSON (an
unescaped quote now terminates the string early). This is the same root
category as C2's bug (two independent text-processing layers — bash and
Python — each doing their own escaping/interpretation pass on the same
text, with the composition breaking silently) but a different concrete
mechanism.

**Fix**: since both reports were already being written to files
(`verifier-output/c3-stale-authcurrency-{disabled,enabled}.json`) for
their own sake, the summarization step was changed to `json.load()` those
files directly instead of re-embedding their text through bash — sidestepping
the shell/Python text-embedding problem entirely rather than trying to
escape it correctly.

### Discarded attempt 2 — `c3-stale-evidence-REPLAY-REJECTED-discarded.jsonl`, `c3-captured-policy-REPLAY-REJECTED-discarded.yaml`, `c3-captured-pre-revocation-evidence-REPLAY-REJECTED-discarded.yaml`

With the JSON-embedding bug fixed, the summarization step ran but produced
a *self-consistent yet wrong* result: `authcurrency_disabled.valid=false`
(not the expected `true`), with the report's own `checks` array showing
`signature` failing (`payload digest mismatch`) and `decision-id`/
`decision-hash`/`policy-hash` all showing `evidence="" policy=""`.

**Root cause**: `run-c3.sh` used a fixed, hardcoded pod/decision name
(`c3-stale-evidence`) across repeated reruns of this script during
debugging. The anti-replay ledger (`operator/internal/controller/decision_ledger.go`)
is a **persistent ConfigMap** keyed by `decision_id`, independent of the
Kubernetes object's own create/delete lifecycle — so even though each
rerun deleted and recreated a fresh `AIPlacementDecision`/
`RuntimeSecurityPolicy` pair, `lib.sh`'s `mint_and_authorize` always
restarts its local `version` counter at 1, and the ledger correctly
rejected the second run's version-1 decision as a replay of the first
run's already-recorded version-1 decision for that same `decision_id`.
The rejected policy's `Status.Decision` was `rejected` with
`verificationStatus: Failed`, and, critically, its `Spec.Binding`/
`Spec.Derivation` were left **empty** (`{}`) — the operator never proceeds
to populate them for a rejected decision. This class of failure was only
caught by permanently saving the captured `policy.yaml`/`evidence.yaml`
(added specifically because of the first discarded attempt's opacity, see
above) and reading `Status.Decision`/`Status.rejectionReason` directly, at
which point the `"decision replay detected"` message made the cause
unambiguous.

The reason this went unnoticed at first: `mint_and_authorize`'s wait loop
checked *only* `RuntimeSecurityPolicy.Status.EnforcementReadyAt` for
success. Per Task 00's original audit, **the agent never reads
`Status.Decision` at all** — it applies whatever `Spec` exists and marks
`EnforcementReady` regardless of whether the operator considers the
decision verified. So a rejected, empty-`Spec` policy still satisfied the
old success check, silently proceeding with a broken policy object instead
of failing loudly.

**Fix, two parts**: (1) `run-c3.sh`'s pod name is now suffixed with
`$RANDOM`, avoiding collision with any prior run's ledger state. (2)
`lib.sh`'s `mint_and_authorize` (shared by C1/C2/C3) now also requires
`Status.Decision == "active"`, and fails loudly with the recorded
`rejectionReason` if it instead observes `"rejected"`, rather than treating
`EnforcementReadyAt` alone as sufficient. This second fix is shared
infrastructure: it would catch this same failure mode in any future rerun
of C1 or C2's scripts too (which also reuse fixed per-condition pod
names across reruns) — though it does **not** retroactively affect C1/C2's
already-collected, retained data, since neither Δ_detect (agent log
timing) nor the evidence fields C1's slow loop reads
(`authorizationState`, `signature.issuedAt`) depend on
`Spec.Binding`/`Spec.Derivation` being populated at all.

### Final, retained run — `raw/c3-stale-evidence.jsonl`

Confirms the intended finding cleanly: `authcurrency_disabled.valid=true`
(every check passes, including signature and the full decision/policy hash
chain) with `authorized_and_compliant=true`; `authcurrency_enabled.valid=false`
with `authorized_and_compliant=false`, and critically, **the sole failing
check is `authorization-currency`** (`ageSeconds=101 maxSeconds=15`) — no
other check fails, isolating the demonstration to exactly the property
this task added rather than an incidental confound. `revocation_confirmed_live=true`
(the live object genuinely showed `authorizationState=revoked` at check
time, so this is not a vacuous result).

## What this pattern says about the harness-building process itself

Three of the four bugs in this task share a structural cause: **composing
two independent text-interpretation layers (bash and Python, or bash and
JSON) without a shared, unambiguous representation.** Each was caught by
noticing a value that was *provably wrong on its face* (a negative
detect-latency-equivalent-of-loss that should be non-negative, a
`NameError` visible in the log, a `JSONDecodeError` visible in the log) --
not by assuming success from a nonzero exit code or a plausible-looking
number.

The fourth (C3's replay-collision) has a different cause: **an
insufficiently strict success check that treated a side-effect
(`EnforcementReadyAt` being set) as proof of an outcome (the decision being
verified/accepted) it did not actually guarantee** -- itself directly
informed by, and a specific instance of, Task 00's own audit finding that
the agent never reads `Status.Decision`. It was caught the same way as the
others: by noticing a downstream value (`decision-id`/`decision-hash` both
empty, a signature that should self-verify not verifying) that was
provably inconsistent, then reading the actual object state rather than
assuming the wait loop's success meant what it appeared to mean.

All four are consistent with the protocol's own rule 27 ("do not make
a scientific claim merely because a test exits 0") applied to harness code,
not just RuntimeGuard itself.

## What was NOT investigated further

- C2's watch-vs-poll comparison was only run at a single poll-interval
  (10s), not swept across the same range as C1 — a time-budget scope
  decision, documented in `summary.md`'s Limitations, not a bug.
