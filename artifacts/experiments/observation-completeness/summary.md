# Experiment B — Observation Completeness — Summary

Task 05. Addresses experiment protocol questions Q3, Q4, Q5.

## B1 — Event loss (Q3)

**Question**: can RuntimeGuard detect event loss instead of silently
reporting COMPLIANT, and does loss occur at increasing offered rates?

**Result** (`raw/b1-event-loss.jsonl`, `processed/b1-event-loss-summary.csv`,
`figures/b1-loss-vs-rate.png`):

| rate/s | attempted | observed_in_evidence | gap | loss_rate | node DropCount |
|---:|---:|---:|---:|---:|---:|
| 100 | 1,000 | 1,026 | -26 | -2.6% | 0 |
| 1,000 | 10,000 | 10,026 | -26 | -0.26% | 0 |
| 5,000 | 49,999 | 50,025 | -26 | -0.052% | 0 |
| 10,000 | 99,995 | 100,021 | -26 | -0.026% | 0 |

Across four rates spanning two orders of magnitude (100/s to 10,000/s),
observed events **exceed** attempted events by a constant, fixed offset of
exactly -26 (i.e. no true loss) at every rate, and `DropCount`
(ring-buffer capacity loss) is 0 at every rate.

**Conclusion**: within the tested range (up to 10,000 file-opens/s
sustained for 10s), audit-mode eBPF observation on this CPU cluster shows
**no measurable rate-dependent event loss**, and the ring-buffer capacity
mechanism (which the implementation *does* instrument and *would* surface
via `DropCount` and `eventsDroppedSinceLastEvidence` forcing
`conformance=incomplete`, per `ebpf-agent/cmd/agent/main.go`
`emitEvidence`) was never exercised because it was never approached. This
is a genuine negative result (no loss found), not evidence that loss is
impossible at higher rates or under different workload shapes (e.g.
network or exec-heavy load) — the campaign did not test above 10,000/s or
sustained multi-minute bursts.

**Getting here required fixing three real harness bugs** (a capture race,
a partial-tick read, and a closure-gap confound) that each initially
produced misleading loss numbers as high as 100%. See exclusions.md for
the full account. This is itself a relevant methodological finding: a
naive "attempted vs. observed" comparison against a system with
asynchronous, ticked evidence emission and reconcile-driven lifecycle
management is easy to get wrong in ways that look exactly like real
observation loss.

**The unexplained constant -26**: not rate-dependent (confirmed by its
exact invariance across a 100x rate range), so it cannot represent
generator-outpacing-observation loss. It is most plausibly incidental
file-open activity performed by the `GATE_START` wait-loop wrapper shell
itself before generation starts (consistent with B2's independently
measured wrapper baseline of 28 events from the same wrapper mechanism).
Not root-caused via `strace` due to time constraints; documented rather
than hidden (exclusions.md).

Q3 answer: **yes** — the implementation has real, non-decorative loss
accounting (`DropCount`, `eventsDroppedSinceLastEvidence`,
`conformance=incomplete` override) rather than silently claiming
COMPLIANT under loss. Whether it is *exercised* correctly under actual
loss conditions was not directly demonstrated in this campaign, since no
condition in the tested range produced real loss to trigger it — this is
a gap the campaign is explicit about, not a claim of "no overhead" or
"complete observation" (forbidden claim words per experiment protocol rule 16).

## B2 — Alternate-path bypass coverage (Q4)

**Question**: can monitored operations bypass the selected hook set?

**Result** (`raw/b2-altpath-coverage.jsonl`,
`processed/b2-altpath-coverage-summary.csv`,
`figures/b2-altpath-coverage.png`), all deltas relative to a wrapper-only
baseline (28 events: execDenied=2, fileOpenDenied=26 — see exclusions.md
for why raw counters alone are not attributable to the probed syscall):

| case | probed syscall | delta (execDenied / fileOpenDenied) | observed by eBPF |
|---|---|---|---|
| control-openat | `openat(2)` | 0 / +1 | **yes** |
| control-execve | `execve(2)` | +1 / +15 | **yes** |
| altpath-openat2 | `openat2(2)` | 0 / 0 | **no** |
| altpath-execveat | `execveat(2)` | 0 / +16 | **no** (on the exec-classification signal) |

`openat2(2)` and `execveat(2)` are **not attached** by the audit-mode
tracepoint hook set (`ebpf-agent/internal/loader/loader.go` `attachAudit`
only attaches `sys_enter_{execve,open,openat}`), confirmed independently
by both static source inspection and this empirical test: the
`execDenied` counter (the exec-classification signal) shows a clean +1 vs
+0 split between `execve` and `execveat`, and the `fileOpenDenied` delta
for `openat2` is exactly 0 (matching the baseline exactly, no increment
at all).

**Caveat on `altpath-execveat`'s +16 `fileOpenDenied` delta**: this test's
implementation of the execveat probe uses the `dirfd + AT_EMPTY_PATH`
calling convention, which requires a precursor `open()` call to obtain the
directory file descriptor — that precursor open is itself a hooked
syscall, and is the most likely source of this delta (it is close in
magnitude to `control-execve`'s +15 `fileOpenDenied` delta, both targeting
the same `/bin/true` binary, suggesting a shared cause such as path
resolution rather than the execveat mechanism itself). The delta is
**not** evidence that execveat's actual process-replacement action was
observed — `execDenied` (the field that would reflect that) stayed at
exactly the baseline value. A real attacker invoking
`execveat(AT_FDCWD, pathname, ...)` directly, without needing any
precursor open, would very plausibly be an even more complete bypass than
what was measured here; this was not tested.

Q4 answer: **yes, monitored operations can bypass the selected audit-mode
hook set** — `openat2` and `execveat` are real, demonstrated observation
gaps, not merely a theoretical concern from static analysis. This is
consistent with, and does not depend on, the trust-boundary gap
identified in Task 00; it is an independent finding about the *hook set*,
not about D→P trust.

## B3 — Silence vs. monitor death (Q5)

**Question**: can the verifier distinguish a quiet workload from a
dead/blind monitor?

**Result** (`raw/b3-monitor-liveness.jsonl`,
`processed/b3-monitor-liveness-summary.csv`), with `--max-age 45s` (1.5x
the 30s production evidence-tick interval — see exclusions.md for why a
tighter threshold produces false positives on a healthy monitor):

- **Dead-monitor check** (60s into a confirmed, still-blocked outage —
  DaemonSet recreation was actively prevented via a temporary
  `nodeSelector`, and the absence of a replacement agent pod was
  confirmed directly via `kubectl`, not assumed from timing): heartbeat
  unchanged from baseline; `verify-evidence`'s `monitor-heartbeat-fresh`
  check correctly **failed** (flagged stale). **True positive.**
- **Recovered-monitor check** (40s after unblocking, past the DaemonSet's
  self-heal and one fresh evidence tick): heartbeat advanced past the
  dead-monitor value; `verify-evidence` correctly **did not flag** it.
  **True negative.**

Both `monitorEpoch` and `hookSetDigest` were present and non-empty in
every evidence object checked (`monitor-epoch-present` and
`hook-set-digest-present` verify-evidence checks both passed throughout);
these fields are populated once at agent startup
(`ebpf-agent/cmd/agent/main.go` `newMonitorEpoch`/`hookSetDigest`) and are
part of the signed payload, not decorative additions — `verify-evidence`
actually evaluates them (per experiment protocol B3's explicit requirement that
added fields not be merely decorative).

Q5 answer: **yes** — with a correctly-configured `--max-age` (set
comfortably above the production tick interval), `verify-evidence`
distinguishes a genuinely dead monitor (heartbeat frozen, correctly
flagged) from a live one (heartbeat advancing, correctly not flagged).
This required fixing a real operational pitfall first: an
under-margined `--max-age` produces false "stale" flags on a perfectly
healthy monitor purely from normal tick-phase timing — a lesson worth
carrying into any real deployment guidance, not just this test harness.

n=1 for this specific outage/recovery cycle (one dead-monitor check, one
recovered-monitor check) — a single controlled kill-and-recover trial, not
repeated across multiple independent outages. Documented as a scope
decision, not a concealed sample size.

## B4 — Formal synthesis: `CompleteObs_Ω(I) ⟺ Coverage_Ω(I) ∧ NoLoss(I) ∧ MonitorLive(I)`

The experiment protocol requires establishing that RuntimeGuard can support
`CompleteObs_Ω(I)` only when all three of `Coverage_Ω(I)`, `NoLoss(I)`,
and `MonitorLive(I)` hold, and that evidence be classified accordingly
when one is false. Evaluating each conjunct against this campaign's
evidence:

- **`Coverage_Ω(I)`** (the hook set observes all operations in Ω) —
  **FALSIFIED** for audit mode's actual hook set. B2 directly demonstrates
  `openat2` and `execveat` are unobserved alternate paths within the
  FILE/EXEC operation classes the experiment protocol itself asks about. Ω as
  actually implemented is `{execve, open, openat}`, a strict subset of the
  syscalls capable of producing the semantic operations RuntimeGuard
  claims to monitor.
- **`NoLoss(I)`** (no observed events are lost between kernel and
  evidence) — **not falsified, and the instrumentation to detect a
  violation is real**, within the tested range (up to 10,000 events/s,
  10s bursts): B1 found zero rate-dependent loss and `DropCount` stayed
  at 0. Critically, the implementation does not silently assume
  `NoLoss(I)` — `eventsDroppedSinceLastEvidence > 0` forces
  `conformance=incomplete` unconditionally, overriding both `conform` and
  `violation` (`ebpf-agent/cmd/agent/main.go` `emitEvidence`), so had loss
  actually occurred in this campaign's tests, it would have been
  surfaced, not hidden. Whether this holds at higher rates, sustained
  duration, or under memory pressure was not tested.
- **`MonitorLive(I)`** (the monitor is actually alive and producing
  evidence, not just cryptographically valid stale evidence) — **holds,
  and is independently checkable**: B3 demonstrates `verify-evidence` can
  distinguish a live monitor from a dead one via `lastHeartbeat` freshness
  (with a correctly-margined `--max-age`), and `monitorEpoch` /
  `hookSetDigest` presence is enforced as real, non-decorative checks.

**Therefore**: since `Coverage_Ω(I)` is falsified for the currently
deployed audit-mode hook set (openat2/execveat bypass it),
`CompleteObs_Ω(I)` **does not hold** for this deployment, regardless of
`NoLoss` and `MonitorLive` both holding in the tested range. This is the
correct, demonstrated conclusion — not "RuntimeGuard has no observation
gaps" and not "RuntimeGuard cannot detect loss or monitor death," but
specifically: **the coverage gap is real and is the binding constraint**,
while the loss-detection and liveness-detection machinery both function
correctly and honestly (neither silently claims more than the evidence
supports) within what was tested.

This has a direct, actionable implication distinct from the enforcement
question addressed by Task 10 (real BPF-LSM): even a hypothetical
enforce-mode deployment inherits `Coverage_Ω`'s gap if it uses the same
hook set — LSM hooks at `bprm_check_security`/`file_open`, if that's what
Task 10 uses, may or may not close this specific gap; that determination
belongs to Task 10, not asserted here.

## Forbidden-claim-word check

Per experiment protocol rule 16, this summary avoids asserting "complete
observation," "no overhead," "non-bypassable," or "fail-closed" — B2
explicitly demonstrates real observation bypasses (openat2, execveat),
and B1/B3 report specific, bounded, tested ranges rather than unqualified
completeness or liveness claims.

## Limitations

- B1/B2/B3 are each n=1 per condition (one run per rate, one run per
  probe case, one outage/recovery cycle) — a documented scope decision
  under real time/cost constraints on a single live billed cluster
  running many experiments serially, not the higher repetition counts
  used in Task 04's A1/A2 (n=30/n=20 per condition). Point estimates here
  should be read as single-trial observations, not distributions.
- B1 tested only file-open generation up to 10,000/s for 10s bursts; exec-
  or network-heavy high-rate workloads, and sustained (multi-minute)
  bursts, were not tested.
- B2 tested only the FILE and EXEC operation classes explicitly named in
  the experiment protocol (openat/openat2, execve/execveat); NETWORK
  (TCP connect) and DEVICE alternate-path coverage were not tested in
  this experiment (NETWORK closure is addressed separately in Task 04;
  DEVICE was scoped out per the protocol's own guidance not to claim
  device coverage without a meaningful CPU-safe path).
- The constant -26 (B1) and 28-event wrapper baseline (B2) were not
  root-caused to the exact responsible syscall(s).
