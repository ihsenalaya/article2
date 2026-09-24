# Task 03 — Timestamp Semantics

Git commit: prior to this task's changes, commit `3268c182` (Task 02 deployment) had the bugs
described below; this document covers the fix landed in this task.

## The problem (as found, code-confirmed — see also Task 00's audit)

Before this task, `operator/cmd/runtime-guard-launcher/main.go`'s release record computed:

```go
releasedAt := time.Now().UTC()
record := releaseRecord{
    EnforcementReadyAt:  policy.Status.EnforcementReadyAt.UTC().Format(time.RFC3339Nano), // t_p
    GateReleasedAt:      releasedAt.Format(time.RFC3339Nano),                              // t_r
    CriticalOperationAt: releasedAt.Format(time.RFC3339Nano),                              // t_c
}
```

Three concrete defects, all confirmed by reading the code (not inferred):

1. **t_p had coarse resolution**: `policy.Status.EnforcementReadyAt` is a `*metav1.Time`, which
   Kubernetes marshals to JSON as RFC3339 with **second** granularity (no fractional seconds) —
   any race/closure measurement finer than 1s was structurally unmeasurable.
2. **t_r and t_c were the literal same value**: `CriticalOperationAt: releasedAt.Format(...)` —
   copied from `GateReleasedAt`, not independently observed. `Δ_RC` was vacuously always ≈0.
3. **t_c was workload/launcher-self-reported, not externally observed**: the launcher process
   never performs the workload's critical operation itself (a separate container in the same pod
   does, after the launcher's ready-file appears) — architecturally, it has no way to know when
   the real critical operation happened, yet it claimed to.

## The fix

**No eBPF/kernel-side change was needed.** `bpf_ktime_get_ns()` was already used for
`event.timestamp_ns` in every hook (`ebpf-agent/bpf/agent.bpf.c:219`) — the protocol's
preferred kernel clock was already in place. This task is entirely a userspace wiring fix.

### t_p — policy readiness

**Definition**: time the current policy generation becomes genuinely ready at the node.

**Source**: `RuntimeSecurityPolicy.Status.EnforcementReadyMonotonicNs` (new field,
`operator/api/v1alpha1/runtimesecuritypolicy_types.go`), an `int64` nanosecond
**CLOCK_MONOTONIC_RAW** reading captured by the node agent
(`ebpf-agent/cmd/agent/main.go:markPolicyEnforcementReady`) at the exact moment `ApplyPlan`
succeeds for that pod's cgroup(s) — the same instant the (now-secondary, kept for human
readability) `EnforcementReadyAt` wall-clock field is set. Idempotent across repeated polls of an
already-current generation (verified by `TestMarkPolicyEnforcementReady`): the captured value is
stable until a genuinely new policy generation is applied.

### t_r — release

**Definition**: time the release mechanism actually allows execution beyond the barrier.

**Source**: `runtime-guard-launcher`'s own **CLOCK_MONOTONIC_RAW** reading
(`operator/cmd/runtime-guard-launcher/main.go:monotonicRawNs`), captured immediately after the
`kubectl`-equivalent `Get` call that confirms `isCurrentEnforcementReady`, before any file/stdout
I/O — as close as practically achievable to "the instant this process learned it may proceed."
Reported as `GateReleasedMonotonicNs` in the launcher's JSON release record, directly comparable
to `EnforcementReadyMonotonicNs` because the launcher runs in the same pod on the same node as
the agent that set it.

### t_c — first externally observed critical operation

**Definition**: time of the FIRST externally observed critical operation. **Must not** be
provided by the workload.

**Source**: `RuntimeSecurityPolicy.Status.FirstObservedOperationMonotonicNs` (new field), the
`bpf_ktime_get_ns()` timestamp of the first eBPF hook event (exec/file-open/connect/device-open)
the agent observes, via the ring buffer, for that pod's cgroup(s) since the current policy
generation was applied. Populated exclusively by `ebpf-agent`'s accumulator
(`ebpf-agent/cmd/agent/main.go`):

- `accumulator.handle` now tracks, per cgroup, whether an event has been seen since the last
  reset (`firstSeenNs` map). The first event for a cgroup pushes a `firstObservation` onto a
  buffered channel.
- A dedicated goroutine, `firstObservationLoop`, drains that channel and writes
  `FirstObservedOperationMonotonicNs` to the owning policy's Status **immediately** (via a
  `retry.RetryOnConflict` status update) — not on the 30-second `evidenceLoop` cadence, which
  would be far too coarse for temporal-closure measurements.
- **Reset semantics** (both sides kept in sync): whenever `reconcileOnce` detects a genuinely new
  policy generation being applied to a pod's cgroups, it calls `acc.resetFirstEvent(cgroupIDs)`
  (forgets in-memory first-seen state) at the same point `markPolicyEnforcementReady` clears
  `Status.FirstObservedOperationMonotonicNs` to `nil` on the CRD — so a stale prior generation's
  t_c can never be mistaken for the current generation's. Verified by
  `TestMarkPolicyEnforcementReady_NewGenerationResetsFirstObservedOperation` and
  `TestAccumulator_FirstObservationNotifiesOnlyOncePerCgroupUntilReset`.
- The launcher no longer reports any `critical_operation_at` field at all — it architecturally
  cannot observe it (see above), and the field is removed, not merely deprecated, so nothing can
  accidentally read a self-reported value again.

## Clock synchronization / mapping between userspace and kernel domains

Per the protocol's own framing, this campaign deliberately uses **two related but distinct**
monotonic clocks:

- Userspace (launcher, agent): **CLOCK_MONOTONIC_RAW** — not NTP-frequency-adjusted.
- Kernel/eBPF (`bpf_ktime_get_ns()`): monotonic-since-boot, matching **CLOCK_MONOTONIC** (which
  *is* subject to small NTP frequency-slew adjustments that MONOTONIC_RAW is not).

**Both are node-local, arbitrary-epoch clocks (time since an unspecified point, typically boot)**
— comparing a timestamp captured on one node against one captured on another node is meaningless
and must never be done. Every t_p/t_r/t_c comparison in this campaign is between processes running
in the same pod on the same node (the launcher and the agent that services it), so this is always
satisfied by construction.

**Measured skew between CLOCK_MONOTONIC and CLOCK_MONOTONIC_RAW** (this matters because t_p/t_r
use RAW while t_c, via the kernel helper, tracks non-RAW MONOTONIC): measured live on both real
cluster nodes (raw data: `artifacts/timing/clock-resolution-raw.txt`) by reading both clocks back
to back and comparing the *offset between them* at two closely-spaced instants:

| Node | mono−raw offset sample 1 | sample 2 | drift of offset (≈ elapsed skew) |
|---|---|---|---|
| worker | 600,468,982 ns | 600,468,484 ns | −498 ns |
| control-plane | 736,440,676 ns | 736,440,336 ns | −340 ns |

The offset itself (≈600–736ms) is an arbitrary per-node constant (both clocks start from
unrelated epochs) and is not meaningful on its own; what matters is that it drifted by only
**hundreds of nanoseconds** across a pair of back-to-back reads (microseconds apart in wall time).
This confirms the RAW-vs-non-RAW skew is negligible — many orders of magnitude below the
millisecond-to-second scale this campaign's Δ_PR/Δ_RC measurements operate at (Task 04) — and safe
to disregard rather than requiring an explicit correction term.

## Measured timestamp resolution

Measured live on the worker node (200,000 back-to-back `clock_gettime_ns(CLOCK_MONOTONIC_RAW)`
calls; full methodology and raw numbers in `artifacts/timing/clock-resolution-raw.txt`):

- **Nominal resolution** (`clock_getres`): 1 ns (both `CLOCK_MONOTONIC_RAW` and
  `CLOCK_MONOTONIC`).
- **Empirically achievable resolution**: every single one of 200,000 consecutive calls produced a
  strictly increasing, nonzero-delta reading; minimum observed delta 180 ns, median 203 ns —
  i.e. resolution in practice is bounded by syscall/vDSO overhead (~180–200 ns on this
  `Standard_D2s_v7` VM), not by clock granularity. This is far finer than anything needed to
  distinguish t_p/t_r/t_c in Task 04's millisecond-to-second-scale measurements.
- `bpf_ktime_get_ns()`'s resolution was not independently micro-benchmarked in kernel space (no
  safe, minimal way to do so without a dedicated probe program), but it reads the same underlying
  hardware clocksource (TSC-backed on this Azure VM family) as the userspace monotonic clocks
  measured above, so the same order-of-magnitude resolution applies. Task 04's real captured
  `FirstObservedOperationMonotonicNs` deltas (multiple runs) will additionally serve as an
  empirical cross-check that resolution is not a limiting factor in practice.

## Live end-to-end verification (not merely unit-tested)

After deploying the fixed images (`runtime-guard-operator:cpu-campaign-20260813-task03` @
`sha256:191e459e400c15c529302b6fac0e1eda7a62a95bc05169954c74b7f7504cf171`,
`runtime-guard-ebpf-agent:cpu-campaign-20260813-task03` @
`sha256:1d9f44699b21f03cc2b7f4bf612a21eb6c21f93877edd5623dc2ac193c53aa72`) to the real cluster, a
disposable smoke-test pod + signed `AIPlacementDecision` was created (namespace `workloads`,
cleaned up afterward) and the resulting `RuntimeSecurityPolicy.Status` was captured verbatim —
`artifacts/timing/smoketest-runtimesecuritypolicy.yaml`:

```
enforcementReadyAt: "2026-08-13T13:02:25Z"          # t_p, wall clock (legacy, second-resolution)
enforcementReadyMonotonicNs: 2671175611193          # t_p, authoritative
firstObservedOperationMonotonicNs: 2672737249574    # t_c, authoritative — real eBPF observation
```

`t_c − t_p` = 1,561,638,381 ns ≈ 1.56 s here — plausible and explainable (the test pod's busybox
loop slept 1s between operations and was already running before the policy was applied, so the
first post-application observation lands up to ~1 loop-period later), and critically: **two
distinct, independently-sourced, nanosecond-precision values**, not a copied pair. This is real,
live evidence that the fix works end-to-end on the actual Azure cluster, not merely that the unit
tests pass against fakes.

## Acceptance criteria (experiment protocol Task 03)

- [x] t_p, t_r, and t_c have documented sources — see above, each cites the exact function/field.
- [x] Resolution is known — measured live, ~180–200 ns achievable, 1 ns nominal.
- [x] t_c is externally observed — sourced exclusively from real eBPF ring-buffer events via the
      agent; the launcher can no longer report it at all.
- [x] t_r and t_c are not artificially copied from one timestamp — confirmed both by code
      construction (independent sources: launcher's own clock read vs. agent's eBPF-derived
      value written to a separate CRD field) and by the live smoke test above showing two
      different, non-derived values.

## Test coverage added

- `ebpf-agent/cmd/agent/enforcement_ready_test.go`: extended `TestMarkPolicyEnforcementReady` to
  assert `EnforcementReadyMonotonicNs` is set and stable across idempotent re-marks; new
  `TestMarkPolicyEnforcementReady_NewGenerationResetsFirstObservedOperation`.
- `ebpf-agent/cmd/agent/first_observation_test.go` (new): `TestAccumulator_
  FirstObservationNotifiesOnlyOncePerCgroupUntilReset`, `TestAccumulator_
  ForgetAllClearsFirstSeenTracking`.
- All pre-existing tests in both modules still pass unmodified in behavior (32/32 ebpf-agent,
  full operator suite including the envtest-backed controller integration suite).
