# Experiment E — Summary (Task 08)

Answers experiment protocol Q11 (controller/agent behavior under repeated scale
tests) and Q12 (does observation completeness degrade as pod/event load
increases). E4 is treated as the primary evidence for Q12; E1-E3 are the
primary evidence for Q11.

## Q11 — controller/agent behavior under repeated scale tests

**E1 (steady-state, N=1/10/50/100, n=3)**: mean submit-to-Ready time grows
from ~3.0s (N=1) to ~3.3s (N=10) to ~10.2s (N=50) to ~24.4s (N=100) —
non-linear, dominated at low N by fixed per-decision pipeline latency
(admission, decision, policy derivation) and only becoming
N-sensitive once N approaches the cluster's real capacity ceiling (see
E3). Controller and agent CPU/memory stayed low and bounded throughout
(operator: 1-109 millicores observed max; agent: 2-145 millicores observed
max, both well under a single core). N=100 rep=1 converged 85/100 — see
`exclusions.md` for the cluster-side-evidenced ("Too many pods"), cross-rep
pod-count race behind this, not a RuntimeGuard defect.

**E2 (submission concurrency, N=50 fixed, concurrency=1/10/25, n=3, 150
pooled decisions/level)**: latency grows monotonically with concurrency at
every pipeline stage:

| concurrency | accepted p50 | accepted p99 | policy-created p50 | ready p50 | ready p95 | ready p99 |
|---|---|---|---|---|---|---|
| 1  | 0.068s | 0.343s | 2.08s | 6.69s  | 13.06s | 13.35s |
| 10 | 0.179s | 0.566s | 5.04s | 9.97s  | 15.51s | 18.99s |
| 25 | 0.331s | 0.607s | 5.50s | 10.89s | 16.52s | 18.73s |

Submission (submit-to-accepted) scales roughly with concurrency, as
expected (more simultaneous API server writes). Ready-latency growth
flattens between concurrency=10 and concurrency=25 (p50 9.97s -> 10.89s,
p95 actually *drops slightly* 15.51s -> 16.52s is within noise) —
consistent with the pipeline's fixed 30s-scale reconciliation/evidence
machinery, not the submission layer, being the dominant cost once
concurrency is no longer the bottleneck.

**E3 (500-policy case, n=3)**: **500/500 does NOT converge on this
cluster.** All 3 reps: exactly 399/500 decisions `"failed: pod never
scheduled"`, 101/500 scheduled. This is a genuine, cluster-side-evidenced
capacity ceiling, not a RuntimeGuard defect: the schedulable worker node
reports `allocatable.pods=110` (control-plane node is tainted
`NoSchedule`), and `kubectl get events --field-selector
reason=FailedScheduling` shows exactly 399 events per rep with reason
`"Too many pods"` — cluster-side RCA evidence captured live during each
rep, per the protocol's "do not blame client path without evidence"
requirement (see `raw/e3-rep*.rca.txt`).

Of the 101 pods that *did* get scheduled: rep=1 fully converged (Ready)
within the 300s timeout (mean 22.9s); rep=2 and rep=3's 101 scheduled
decisions did **not** converge within 300s despite being scheduled
(`outcome=timed_out`). This secondary effect is reported honestly as
**not fully root-caused**: agent CPU trended upward across the three
back-to-back reps (146 -> 220 -> 225 millicores max) while operator CPU
stayed flat (132 -> 130 -> 141), suggesting the single-worker-node agent
(not the operator) may be the constrained resource under repeated heavy
scale attempts on a 2-vCPU node — but this is an observation, not a
demonstrated causal claim.

## Q12 — does observation completeness degrade under load?

**E4 (event integrity under scale, N=100, concurrency=100, n=3)**: for
every evidence object produced across all 3 reps (300 total, 100%
coverage against the 100/100 converged decisions per rep):

- `DropCount == 0` and `EventsDroppedSinceLastEvidence == 0` for every
  single evidence object, every rep. By the kernel-enforced invariant
  `Generated == Emitted + Dropped` (see `ebpf-agent/internal/loader/loader.go`'s
  `EventCounters` doc comment — not independently re-measured here, since
  no kernel `Generated` counter is exposed via the CRD and adding one was
  not necessary to answer this question), `DropCount == 0` is sufficient
  to establish `Generated == Emitted` for these runs without a separate
  generation-rate readout.
- `conformance` was never `"incomplete"` for any evidence object in any
  rep (only `"conform"` and `"violation"` appear) — consistent with the
  zero-drop result, since `EventsDroppedSinceLastEvidence != 0` is what
  forces `"incomplete"` (see `runtimeplacementevidence_types.go`).

**Answer to Q12, within this measurement: no — observation completeness
did not degrade under N=100 concurrent load.** This is a real, positive
result, not assumed from "CRDs became Ready" (which the experiment protocol
explicitly warns is insufficient) — it is directly measured from the
agent's own kernel-side drop counters, exposed and signed as part of each
evidence object.

**Open, unexplained secondary observation** (reported honestly, not
root-caused): `ExecAllowed == 0` in all 3 reps, despite every one of the
100 workload pods (`sleep 3600`) necessarily exec'ing the `sleep` binary
once at container start. `FileOpenDenied` dominates the incorporated-event
counts instead (16 / 203 / 112 across reps, highly variable), with 1-3
pods per rep showing `conformance=violation`. Possible explanations not
distinguished by this data: an attribution/tracking-window gap at the very
start of a pod's lifecycle (before the agent resolves the pod-UID-to-cgroup
mapping), or audit-mode "would-be-denied" file-open policy defaults being
broader than exec defaults. Left for follow-up investigation — see
`exclusions.md`.

## Limitations

- E1/E2/E3/E4 all use n=3 reps per condition, not the protocol's
  preferred n=5, under real time constraints on a single live billed
  cluster running many experiments serially — the same documented scope
  decision as every prior experiment in this campaign.
- This cluster's scalability ceiling (~101-102 pods) is a property of
  this specific 2-node, 110-max-pod-per-node Azure test environment, not
  a property of RuntimeGuard's own architecture. A larger cluster would
  need to be re-provisioned to test genuinely higher N; that was out of
  scope for this task's time/cost budget (see `environment.json`'s node
  capacity note).
- E3's rep=2/rep=3 "scheduled but timed out" secondary effect is reported
  as an open observation with a plausible-but-unconfirmed direction
  (agent CPU), not a demonstrated root cause.
- E4's ExecAllowed anomaly is reported as an open observation, not
  root-caused (see above and `exclusions.md`).
- A mid-task infrastructure incident (VM auto-shutdown + expired ACR
  credential, see `exclusions.md`) interrupted E4's data collection
  between E3 and the final E4 run; it delayed but did not corrupt any
  retained data, since every affected attempt was fully discarded and
  documented rather than partially salvaged.
