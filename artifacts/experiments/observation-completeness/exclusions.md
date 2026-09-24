# Exclusions and discarded runs — Experiment B (Task 05)

Per the protocol's rule 21: failed/invalidated runs are never silently
deleted. This file records every discarded attempt, why it was discarded,
and what it changed about the final methodology. The raw discarded data
itself is retained under `discarded-runs/` (not counted in any reported
statistic).

## B1 (event loss): four discarded sweeps, three real bugs found and fixed

### Attempt 1 — `b1-event-loss-PRE-LINGER-FIX-discarded.jsonl`

First B1 attempt. rate=100 showed loss_rate=0.367; rate=1000 showed
loss_rate=**1.0** (0 of 10000 events observed) — a discontinuous jump with
no rate-dependent explanation.

**Root cause**: `rate-gen` exits as soon as its paced generation completes.
Without a linger period, the pod goes `Completed`, and the agent's
reconcile loop can race ahead to revoke + `forgetAll` (which wipes
per-cgroup accumulator state outright) before the next 30s evidence tick
ever captures the accumulated counters. This is a harness bug, not a
RuntimeGuard observation-completeness defect.

**Fix**: `lib.sh`'s `create_policy_bound_pod` now wraps the tool invocation
in a shell that sleeps `POD_LINGER_SECONDS` (default 90s, raised to 120s
for B1) after the tool exits, keeping the cgroup alive long enough for
evidence to be captured before cleanup.

### Attempt 2 — `b1-event-loss-PRE-STABLE-READ-FIX-discarded.jsonl`

After the linger fix, loss rates were non-zero but noisy and
non-monotonic across rates (61.7% / 23.65% / 68.0% / 34.8%).

**Root cause**: the evidence loop uses a single global 30s ticker across
all tracked pods with cumulative per-cgroup counters. The polling loop
broke on the *first* non-empty `behavior_json` read, which can catch a
tick that fired mid-generation or immediately after pod creation —
essentially a random mid-window snapshot, not the complete count.

**Fix**: replaced "poll until first non-empty, then use it" with a fixed
wait of `duration + 40s` (>= one full tick past generation end) followed
by exactly one read.

### Attempt 3 — `b1-event-loss-PRE-YAML-QUOTE-FIX-discarded.jsonl`

After adding `GATE_START` (see below) to fix a third confound, the very
first rerun failed outright: `error parsing STDIN: error converting YAML
to JSON: yaml: line 14: did not find expected ',' or ']'` on every rate.

**Root cause**: the gated `inner_cmd` shell script contains literal double
quotes (`"$0" "$@"`). Embedding it inside an already-double-quoted YAML
flow-sequence element (`"$inner_cmd"`) broke YAML parsing. No pods were
even created; this is a pure syntax bug with zero scientific content.

**Fix**: switched that array element to single-quoted YAML (`'$inner_cmd'`),
verified against `python3 -c "import yaml..."` before rerunning against
the live cluster.

### Attempt 4 — `b1-event-loss-PRE-GATE-FIX-discarded.jsonl`

Before the YAML fix (attempt 3), and orthogonal to it: raw counters (prior
to the `GATE_START` gating mechanism) showed loss consistently higher at
rate=100 (~60%) than at higher rates (~20-31%), with `DropCount` staying
at 0 throughout (confirming ring-buffer capacity was never the cause).

**Root cause**: `rate-gen` starts executing immediately at container start
— concurrently with, and potentially substantially overlapping, the
harness's own decision-minting and `EnforcementReady` wait (which can take
several seconds, more on a cold start). rate=100 ran first in the sweep
and plausibly experienced a longer closure gap (cold Go build cache,
first scheduling on the node), inflating its apparent loss. This
confounds B1's intended measurement (observation completeness of an
*already-enforced* pod) with Task 04's admission-to-release closure gap —
a different, already-measured phenomenon.

**Fix**: added `GATE_START=1` support to `lib.sh`. The tool's container
command now blocks on `/tmp/start-generating` before running; the harness
only `kubectl exec`s that file into existence after `EnforcementReady` is
externally confirmed, so generation cannot start until policy application
is complete.

### Final, retained run — `raw/b1-event-loss.jsonl`

With all three fixes applied together, loss is near-zero and **not**
rate-dependent: a constant delta of exactly **-26** events (observed
slightly *exceeds* attempted) at every one of the four rates (100, 1000,
5000, 10000/s), and `DropCount` (ring-buffer capacity loss) stayed at 0
throughout. The constant -26 is not chased further (see summary.md) — it
does not scale with rate or duration, so it cannot represent rate-loss; it
is most plausibly incidental file-open activity from the gate-wait wrapper
shell itself (consistent with the wrapper-baseline measurement made
independently in B2, which found a very similar-magnitude baseline of 28
events from the identical wrapper mechanism).

## B2 (alternate-path coverage): one discarded run, one real ambiguity fixed

### Discarded — `b2-altpath-coverage-PRE-BASELINE-FIX-discarded.jsonl`

First B2 attempt reported `observed_by_ebpf=True` for **all four** cases,
including `altpath-openat2` and `altpath-execveat`, which static analysis
of `ebpf-agent/internal/loader/loader.go` predicted should NOT be
observed (audit mode only attaches `sys_enter_{execve,open,openat}`).

**Root cause**: raw (non-delta) Behavior counters include real wrapper
overhead — the `GATE_START` wait loop and the shell's own fork+exec of the
probe binary. This was confirmed decisively: `execDenied=2` appeared even
for the `openat2` case, which makes **zero** exec calls internally. A
nonzero raw counter therefore could not distinguish "the probed syscall
was observed" from "the wrapper's own baseline activity was observed."

**Fix**: added a wrapper-only baseline measurement (`altpath-probe` called
with an unrecognized mode, which its `default:` branch handles by exiting
before any file/exec syscall) and switched `observed_by_ebpf` to a
baseline-subtracted delta. The baseline (execDenied=2, fileOpenDenied=26)
matched the discarded openat2 case's raw numbers almost exactly,
confirming the hypothesis. The final run showed a clean split:
`execDenied` delta of +1 for `control-execve` vs. +0 for
`altpath-execveat`; `fileOpenDenied` delta of +1 for `control-openat` vs.
+0 for `altpath-openat2`.

## B3 (monitor liveness): two discarded runs, two real timing bugs

### Attempt 1 — `b3-monitor-liveness-PRE-MIDOUTAGE-FIX-discarded.jsonl`

First B3 attempt waited the full 45s outage window before checking
anything. By then the DaemonSet had already self-healed and emitted a
fresh heartbeat, so `verify-evidence` correctly reported FRESH — the test
never actually observed a "monitor genuinely dead" state at all, despite
being designed to.

**Fix**: split into a mid-outage check (during the outage, before
self-heal can plausibly complete) and a post-recovery check.

### Attempt 2 — `b3-monitor-liveness-PRE-MAXAGE-FIX-discarded.jsonl`

With the mid-outage/post-recovery split added, the mid-outage check at
15s post-kill correctly showed `flagged_stale=false` (age=15-17s, under
the 20s `--max-age` used) — an unremarkable true negative, but not the
intended true positive. Worse, the *post-recovery* check (which should
have shown a healthy, non-stale monitor) instead showed
`flagged_stale=true` with age=30s.

**Root cause**: `--max-age 20s` is shorter than the system's actual 30s
evidence-tick interval. A perfectly healthy monitor's heartbeat naturally
ranges 0-30s old between ticks (sawtooth pattern), so any max-age below
the tick interval produces false "stale" flags on a live monitor roughly
`(interval - max_age) / interval` of the time, purely from tick-phase
timing — independent of any real outage. This is a genuine, generalizable
operational lesson (see summary.md), not just a test-script bug: any
deployment choosing `--max-age` must set it comfortably above the
production evidence interval, or false positives are inevitable.

A second, related issue found in this attempt: the DaemonSet self-heals
fast enough (~30-45s, since Kubernetes recreates the pod within seconds
and the new agent's first evidence tick fires ~30s after its own start)
that there was no reliable window to observe a heartbeat both older than
a properly-margined max-age (e.g. 45s) AND still genuinely dead, using
sleep-based timing alone.

**Fix**: (1) raised `--max-age` to 45s (1.5x the 30s tick interval,
matching `experiment-config.json`'s documented rationale). (2) Blocked
DaemonSet recreation deterministically via a temporary `nodeSelector`
patch that no node satisfies (node taints do **not** work here — the
DaemonSet's pod template tolerates all taints, `{"operator":"Exists"}`),
confirmed directly via `kubectl get pods` that no replacement agent
existed during the blocked window, rather than assuming it from a sleep
duration.

### Final, retained run — `raw/b3-monitor-liveness.jsonl`

Dead-monitor check (60s into a confirmed, still-blocked outage):
heartbeat unchanged from baseline, `verify-evidence` correctly flags
stale (true positive). Recovered-monitor check (40s after unblocking):
heartbeat advanced, `verify-evidence` correctly does not flag it (true
negative). Both are n=1 (a single controlled outage/recovery cycle); see
summary.md for the sample-size discussion.

## What was NOT investigated further (documented, not hidden)

- The constant **-26** event delta in B1 and the wrapper-baseline of **28**
  events in B2 were not root-caused down to the exact syscall(s)
  responsible (e.g. via `strace` inside the container). Both are small,
  non-rate-dependent, and do not change either experiment's qualitative
  conclusion, but a future campaign could confirm the exact source rather
  than the plausible-but-unconfirmed "gate-wait wrapper shell activity"
  hypothesis offered here.
- B1, B2, and B3 are each n=1 per condition (one run per rate / per case /
  one outage-recovery cycle), not the higher repetition counts used in
  Task 04. This is a documented scope decision under real time and cost
  constraints on a live billed cluster running many experiments serially,
  not a concealed sample size — see experiment-config.json and
  summary.md's limitations section.
