# Exclusions and discarded runs — Experiment E (Task 08)

Per experiment protocol rule 21: failed/invalidated runs are never silently
deleted. This file records every discarded attempt from this task, why it
was discarded, and what it changed about the final methodology. Raw
discarded data is retained under `discarded-runs/` (not counted in any
reported statistic).

## E1 (steady-state): two discarded sweeps, one real bug found and fixed

### Attempt 1 (`e1-n1-rep1-26480.json` ... `e1-n50-rep1-22772.json`, `e1-steady-state-partial-run1.jsonl`)

First E1 attempt. N=1 rep=2 crashed the analysis step
(`TypeError: 'NoneType' object is not iterable`) on a null
`metrics_samples` field — a legitimate outcome (convergence can finish
before the first 2s metrics tick ever fires for small/fast N), not a
generator bug, but the analysis script didn't guard for it. The fix
(`samples = d['metrics_samples'] or []`) was applied to `run-e1.sh` on
disk *while the sweep was still running in the background*, so N=10 and
N=50 rep=1 ran under an inconsistent mix of old/new analysis code before
N=50 rep=1 then hit a second, unrelated crash (`JSONDecodeError`, empty
captured output — see below). Discarded in full rather than trying to
salvage the N=1/N=10 records collected before the crash, to keep the
sweep's code version consistent throughout.

### Attempt 2 (`e1-n1-rep1-13363.json` ... `e1-n100-rep3-8326.json`, `e1-steady-state-partial-run2.jsonl`)

Rerun from scratch with the null-metrics fix applied cleanly. N=1/N=10/N=50
all converged 100% across all reps. N=50 and N=100 then hit a **new**
failure: `run_scale_job`'s log capture returned empty/unparseable output
6 times in a row (every N=50 and N=100 rep).

**Root cause**: client-go's default QPS=5/Burst=10 is far below the
concurrency this generator drives (N=50, N=100). Client-side throttling
fired, and client-go logged a `"Waited for Xs due to client-side
throttling"` line via klog. Container runtimes (containerd here) combine
a container's stdout and stderr into one interleaved log stream — so
`kubectl logs` returned that klog line *ahead of* the generator's single
JSON result line (written last, to stdout, right before exit), and the
whole capture failed to parse as JSON.

**Fix, two parts**: (1) `operator/cmd/scale-generator/main.go` now raises
`restConfig.QPS`/`Burst` to 200/400, removing the throttling (and its log
line) at the concurrencies this generator actually drives — a genuine
scalability-relevant fix in its own right, not just a log-hygiene one.
(2) `lib.sh`'s `run_scale_job` now takes the **last line** of the captured
log as the JSON payload (with retry-with-backoff if that line isn't valid
JSON yet), rather than assuming the whole capture is pure JSON — a
correctness fix independent of (1), since nothing guarantees no other
stderr line could ever appear in that combined stream.

Discarded in full (all N tiers) rather than only rerunning the two failed
tiers, so the retained E1 run uses one consistent generator image
throughout (`scale-generator:task08-qpsfix`).

### Final, retained run — `raw/e1-steady-state.jsonl`

All 12 reps (4 tiers × 3) produced valid data with the fixed image. N=100
rep=1 shows 85/100 converged (15 "pod never scheduled") — this is
**retained as a genuine finding**, not excluded: direct cluster evidence
(`kubectl get events --field-selector reason=FailedScheduling`) shows
`"Too many pods"` on the worker node at the time, consistent with the
previous rep's (N=50 rep=3) terminating pods still occupying pod-count
slots when N=100 rep=1's decisions were submitted only 3s later. This
motivated hardening `cleanup_scale_run` (see below) before E2/E3/E4 ran,
but the already-collected E1 data is reported as-is, including this
partial-convergence result.

**Hardening applied for E2/E3/E4 (not retroactive to E1)**:
`cleanup_scale_run` changed from `--wait=false` to `--wait=true
--timeout=120s`, so each rep's pods are confirmed gone before the next
rep submits, isolating each rep's condition from the previous one's
teardown tail. This is why E2/E3/E4 do not show the same cross-rep
contamination pattern E1's N=100 rep=1 does.

## E4 (event integrity): three attempts, two real bugs plus one infrastructure incident

### Attempt 1 — `discarded-runs/e4-event-integrity-partial-run1.jsonl` (0 records), `discarded-runs/e4-rep{1,2}-*.evidence.json`

Both rep=1 and rep=2 crashed identically:
```
File "<string>", line 3
    with open('FAILED
SyntaxError: unterminated string literal
```
**Root cause**: `lib.sh`'s job-failure diagnostic path had
`kubectl -n "$NS" logs "job/$job_name" --tail=-1 2>&1 >&2` — a classic
redirect-order bug. `2>&1` first makes fd2 a copy of fd1's *current*
target (the pipe `run_scale_job`'s caller captures via `$(...)`); `>&2`
then makes fd1 a copy of fd2's *new* target — which is now that same
pipe. Net effect: both fd1 and fd2 end up writing to the captured pipe,
so the intended "print failed-job logs to stderr for visibility" line
instead appended a full raw job-log dump to the captured stdout, right
after the `echo "FAILED"` that preceded it. The caller's exact-match
check (`[ "$out_path" = "FAILED" ]`) then failed to match this multi-line
"FAILED\n<log dump>" string, falling through into the success path, which
tried to `open()` the corrupted multi-line string as a Python source
fragment.

This bug had existed in `lib.sh` since it was first written for E1, but
was never exercised until E4 rep=1/2 hit a *genuine* Job-level failure —
E1/E2/E3's earlier "FAILED" outcomes all went through the (unrelated,
already-correct) log-capture-retry path, which never had this bug.

**Fix, two parts**: (1) the diagnostic `kubectl logs` call now writes to
a dedicated file (`raw/<run_id>.failed-job-logs.txt`) instead of using
any stdout/stderr redirect trick at all. (2) every caller script's check
was hardened from `[ "$out_path" = "FAILED" ]` to
`[ "$out_path" = "FAILED" ] || [ ! -f "$out_path" ]`, so any future
similar corruption fails safe (falls into the job_failed branch) instead
of crashing.

### Attempt 2 — `discarded-runs/e4-event-integrity-partial-run2-wrongns.jsonl`

With the above fixed, this attempt completed cleanly (100/100 converged,
all 3 reps) but reported `n_evidence_objects: 0` /
`evidence_coverage: 0.0` for every rep. **This was a script bug, not a
RuntimeGuard finding**: `run-e4.sh` queried
`kubectl -n workloads get runtimeplacementevidence`, but the agent's
`--evidence-namespace` default is `aiops-system`, not the workload
namespace the pods/decisions live in. Fixed by querying `aiops-system`
directly (the run's evidence objects are still uniquely identified by the
`scale-<run_id>-` name prefix, filtered out of the ~2400 evidence objects
`aiops-system` had accumulated from earlier tasks in this campaign — none
of which share this run's `$RANDOM`-suffixed run_id).

### Infrastructure incident between attempts 1/2 and the final run

Both cluster VMs were deallocated by a pre-existing daily 23:00 UTC
DevTestLab auto-shutdown schedule (a Terraform/subscription default this
campaign had not intentionally set) during a scheduled wait period.
Restarting them surfaced a second, independent problem: the
`acr-pull-secret` in every namespace held a short-lived (~3h15m) ACR OAuth
refresh token that had expired during the outage, causing
`ImagePullBackOff` on every subsequent scale-generator Job (E4 rep=3's
first sub-attempt, inside attempt 1 above). Fixed by enabling the ACR's
admin user and recreating the pull secrets with the resulting static
credential — with one further self-inflicted wrinkle: the first
recreation attempt piped `az acr credential show ... -o tsv` directly into
`--docker-password=`, which carried a trailing `\r` (Windows-style line
ending in the CLI's tsv output) into the secret, still producing `401
Unauthorized`. Caught by testing the credential directly against the ACR
OAuth endpoint with `curl` before re-blaming Kubernetes; fixed by piping
through `tr -d '\r\n'`. The auto-shutdown schedule was disabled on both
VMs to prevent recurrence for the remainder of this campaign.

### Final, retained run — `raw/e4-event-integrity.jsonl`

100/100 evidence coverage, `DropCount==0` and
`EventsDroppedSinceLastEvidence==0` for every evidence object, across all
3 reps. See `summary.md` for the finding and its interpretation, and for
an honestly-unresolved secondary observation (ExecAllowed==0 despite every
pod exec'ing at container start).

## What this pattern says about the harness-building process itself

Three of this task's four software bugs (the null-metrics crash, the
throttling/log-interleave corruption, the redirect-order corruption) share
the same structural root as bugs found in earlier tasks' harnesses (see
`revocation/exclusions.md`): composing shell, a container runtime's log
stream, and Python's `-c` source-text embedding without a representation
that's safe under composition. Each was caught the same way those were —
by noticing a value or crash that was provably wrong on its face
(`TypeError`, `SyntaxError`, a `0.0` coverage rate implying nothing was
ever measured), not by assuming a nonzero exit code meant nothing to
investigate. The fourth (wrong evidence namespace) was caught by knowing
what the agent's actual default flag value is and checking it against
what the script assumed, rather than trusting the plausible-looking
"0 evidence objects" number without checking where evidence objects
actually live.

## What was NOT investigated further

- E4's ExecAllowed==0 / FileOpenDenied-dominant pattern is reported as an
  open observation (see summary.md), not root-caused. Confirming why the
  container's initial `sleep` exec is apparently not attributed as
  ExecAllowed would require agent-side code investigation (cgroup-to-PID
  attribution timing relative to hook attach) out of scope for this task's
  time budget.
- E3's rep=2/rep=3 "scheduled but never converged within 300s" secondary
  effect (distinct from the "never scheduled" majority) was not
  independently root-caused beyond the operator/agent CPU trend noted in
  summary.md — a time-budget scope decision, not a bug being hidden.
