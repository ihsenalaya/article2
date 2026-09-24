# Experiment A — Summary (Task 04)

Git commit: `a74c545a6d9283ecf55fba6e7dace646615ac7c9` (Task 03's fix) plus this task's
`inject-ready-delay-ms` test-harness hook. Full stats: `processed/closure-summary-stats.csv`.
Figures: `figures/delta_pr_ns-by-condition.png`, `figures/delta_rc_ns-by-condition.png`. All
numbers below are computed programmatically by `scripts/analyze.py` from `raw/*.jsonl` — none
edited by hand.

## Total runs

435 independent pod lifecycles: A1=30, A2=80 (4×20), A3=305 (5×1 + 5×10 + 5×50), A4=10, A5=10.
12 of A3's 305 (3.9% of A3, 2.8% of the campaign) are excluded from the statistics below —
retained and explained in `exclusions.md`, not dropped.

## Q2 — Distributions of Δ_PR and Δ_RC under normal and stressed startup

**A1 (nominal, cooperative, n=30):**

| Metric | n | mean | median | SD | min | max | P5 | P95 |
|---|---|---|---|---|---|---|---|---|
| Δ_PR (ms) | 30 | 54.7 | 53.8 | 29.9 | 11.1 | 101.8 | 14.8 | 99.1 |
| Δ_RC (ms) | 30 | 2882.1 | 614.8 | 4630.9 | 612.6 | 13926.3 | 612.8 | 11729.5 |

Δ_PR is tightly bounded by the launcher's 100ms poll interval (min never below ~11ms, i.e. the
launcher never releases before the agent's own readiness timestamp — see Q1 below). Δ_RC is
**heavy-tailed**: median (615ms) is close to the minimum, but the mean is pulled far above it by a
real long tail (max 13.9s) — most runs observe the critical operation promptly after release, but
a meaningful minority take many seconds, most plausibly variance in container-start latency for
the main workload container plus the agent's poll cycle needing to discover a cgroup that did not
exist at release time (the fail-open startup-window mechanism documented in Task 00 §3 — a new
cgroup gets no observation until the *next* poll cycle notices it).

**A2 (policy-readiness stress, artificially delayed policy application, n=20/delay):**

| Delay injected | n | Δ_PR median (ms) | Δ_PR min (ms) | Δ_PR max (ms) | Δ_PR < 0? |
|---|---|---|---|---|---|
| 0ms | 20 | 53.4 | 9.7 | 101.9 | never |
| 50ms | 20 | 49.3 | 7.7 | 99.5 | never |
| 250ms | 20 | 62.4 | 7.3 | 83.3 | never |
| 1000ms | 20 | 47.7 | 8.3 | 84.7 | never |

**Δ_PR ≥ 0 held in all 80/80 A2 runs**, across every delay condition including the most aggressive
(1000ms artificial policy-application delay). Δ_PR's magnitude does **not** scale with the
injected delay — this is expected and explainable, not a null result: the injected delay shifts
*when* t_p occurs in absolute time (it happens before `ApplyPlan`/`markPolicyEnforcementReady`),
but the *race margin* the launcher experiences is governed by its own 100ms poll interval against
whatever the (now-later) t_p turns out to be, not by the delay's magnitude itself. This is a
genuine, positive robustness finding for the release protocol's internal timing correctness — it
does **not** by itself establish "non-bypassable" (see Q1).

**A3 (concurrency stress, 1/10/50 concurrent submissions):**

| Concurrency | n (success/total) | Δ_PR median (ms) | Δ_PR min (ms) | Δ_PR P95 (ms) |
|---|---|---|---|---|
| 1 | 5/5 | 35.9 | 33.2 | 75.0 |
| 10 | 50/50 | 69.7 | 10.6 | 305.2 |
| 50 | 238/250 | 7739.6 | 6.8 | 25590.8 |

**Correctness held under all tested load** — Δ_PR was never negative in any of the 293 successful
runs across all three concurrency levels. **Performance did not** — median Δ_PR grew from 36ms
(c=1) to 70ms (c=10) to **7.7 seconds** (c=50), a ~220× degradation, with P95 reaching 25.6
seconds and Δ_RC's P95 reaching 32.9 seconds at c=50. `min(Δ_PR)` (the protocol's specifically
requested lower-tail statistic) stayed positive throughout (6.8ms floor at c=50), so the timing
*safety* margin never inverted even under the heaviest tested load — but the system's practical
usability at c=50 on this 2-node cluster is severely degraded, and 12/250 runs (4.8%) failed
outright for reasons traced to a real infrastructure fault this load exposed (see `exclusions.md`
— Calico IPIP encapsulation breaking down on Azure under sustained high pod churn, fixed by
switching to VXLAN mid-experiment).

## Q1 — Is the release mechanism a non-bypassable barrier or a cooperative protocol?

**Established directly, not merely asserted:**

1. **The `runtime-guard-launcher` gate is cooperative by construction** (already established
   statically in Task 00 §3, and unchanged by this experiment): it is a userspace binary a
   workload's container spec chooses to run as an initContainer. Nothing prevents a pod from
   omitting it.

2. **A4 (mandatory non-cooperative control, n=10)**: a workload with no launcher, no wait logic,
   attempting its critical operation immediately at container start, was tested against a real
   signed decision/policy. In all 10 runs, the eBPF-observed first operation
   (`FirstObservedOperationMonotonicNs`) occurred **after** the agent's own policy-ready timestamp
   (`EnforcementReadyMonotonicNs`) — `operation_observed_before_policy_ready = false` in 10/10
   runs, i.e. no bypass was *observed*.

   **This must not be over-interpreted.** Per Task 00 §3's static finding, an operation is only
   ever recorded by this mechanism if it happens in a cgroup that already has a `cgroup_configs`
   entry; an operation that races ahead of *both* the launcher and the agent's policy-application
   poll cycle is **architecturally invisible** to eBPF (fail-open, unobserved — no event is
   emitted at all, so nothing updates `FirstObservedOperationMonotonicNs`). A truly early bypass
   would not show up as `operation_observed_before_policy_ready = true`; it would show up as
   `first_observed_operation_monotonic_ns` reflecting a *later* operation than the workload's real
   first attempt, indistinguishable in this data from "no bypass occurred." **This experiment
   therefore cannot rule out an unobserved bypass in the fail-open window** — it can only report
   that no *observed* bypass occurred in this sample. Resolving this ambiguity requires exactly
   the generated-vs-observed event accounting that Task 05 (Observation Completeness) is scoped to
   build.

3. **A5 (no-policy negative control, n=10)**: confirms the complementary half of the picture —
   with no decision/policy ever created, `RuntimeSecurityPolicy` and `RuntimePlacementEvidence`
   never exist for the pod (0/10 in both cases). The system has **no record at all** of an
   unauthorized workload's attempt, consistent with (and now empirically demonstrating) Task 00's
   static fail-open finding: absence of a policy means absence of observation, not denial.

**Conclusion**: the release mechanism, as currently implemented, is a **cooperative
synchronization protocol**, not a demonstrated non-bypassable barrier. Its internal timing logic
is verifiably correct (Δ_PR never negative across 373 successful cooperative/stress runs spanning
A1-A3), and A4 found no *observed* bypass in 10 runs — but per Task 00's code-level analysis and
this experiment's own epistemic limits, that absence of observed bypass is not equivalent to a
proof of non-bypassability, because the measurement instrument itself has a documented blind spot
during the fail-open startup window. The word "non-bypassable" (forbidden without direct
demonstration per experiment protocol rule 16) is not used to describe this system.

## Negative/qualified results (preserved, not smoothed over)

- 12/250 (4.8%) A3 concurrency=50 runs failed outright under load (`exclusions.md`).
- A discovered, real cluster networking fault (Calico IPIP incompatibility with Azure under
  sustained load) required an infrastructure fix mid-experiment.
- A4's "no observed bypass" result is explicitly qualified as inconclusive regarding true
  non-bypassability, not reported as a clean pass.
- Δ_RC's heavy right tail (up to 13.9s at nominal load, 37.2s at c=50) is reported in full, not
  summarized only by its more favorable median.
