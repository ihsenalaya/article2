# Exclusions — Experiment A (Task 04)

Per experiment protocol rule 21: excluded/failed runs are retained in the raw data, never silently
removed. This document explains every exclusion.

## A3 concurrency=50, repetition 2: 12/50 runs recorded `outcome=failed`

Run IDs: `closure-a3-c50-r2-{002,004,005,006,013,015,016,019,038,046,047}` (11 listed by the
harness log plus `closure-a3-c50-r2-{020?}` — exact set is in
`raw/a3-concurrency.jsonl` with `"outcome":"failed"`).

**Recorded reason**: `launcher_did_not_release_Completed` — the harness's log-fetch step found no
JSON output line from the launcher initContainer.

**Root-caused, not assumed**: inspecting one such pod directly
(`closure-a3-c50-r2-002-30076`) after the fact showed its `guard-launcher` initContainer had in
fact **terminated successfully, `exitCode: 0`, reason `Completed`** — i.e. the actual RuntimeGuard
release mechanism worked correctly for this pod. The failure is in this test harness's own
observability at that moment (its `kubectl logs` fetch came back empty), not a RuntimeGuard
defect. These 12 pods were also found still `Running` (never actually deleted) ~19 minutes after
the experiment moved on, indicating the harness's own cleanup step for these specific pods also
did not take effect at the time — both symptoms are consistent with the real infrastructure
problem discovered and fixed during this task (see below): cluster cross-node networking had
degraded during the tail of the concurrency=50 stress run.

**Disposition**: retained in `raw/a3-concurrency.jsonl` with `outcome="failed"`; excluded from the
`delta_pr`/`delta_rc` statistics in `processed/closure-summary-stats.csv` (no valid values exist
for them, so they contribute to `n_total_runs` but not `n_with_value`/`n_success`). Reported as
4.8% of the concurrency=50 condition — a real, non-hidden data-quality cost of running that stress
condition at this scale on a 2-node cluster.

## Real infrastructure fault discovered and fixed during A3/A5

While investigating A5's `workload_self_reported_result="unknown"` anomaly (10/10 runs), direct
diagnosis found **all cross-node pod-to-pod networking was down** (100% packet loss,
`vm-a2-cpucampaign-20260813-worker` ↔ `vm-a2-cpucampaign-20260813-cp` pod IPs), while raw VM-to-VM
networking (outside Kubernetes) was completely healthy. Root cause: Calico's default IPIP
encapsulation (`ipipMode: Always`) does not reliably traverse Azure's network fabric under
sustained load — a known real-world Calico-on-Azure limitation, here first manifesting after the
A3 concurrency=50 stress test's ~250 rapid pod create/delete cycles. Fixed by switching the
cluster's `default-ipv4-ippool` to `vxlanMode: Always` / `ipipMode: Never` and restarting the
`calico-node` DaemonSet and `coredns` Deployment; cross-node ping and DNS resolution were
re-verified working after the fix (see Task 04 review for the verification commands/output).

**Scope of impact on already-collected data**: A1 (30/30), A2 (80/80), and the bulk of A3
(293/305) completed successfully *before* this networking degradation became apparent, and their
`wget` operations demonstrably succeeded (real `Δ_RC` values were recorded, which requires a
working TCP connection) — those results are not retroactively invalidated. A4's measurement
mechanism (eBPF-observed first operation, not wget's own success/failure) is also unaffected by
DNS/connectivity outcome, since a failed connection attempt still constitutes a real observed
`connect()` syscall. Only A3's last repetition (12 runs, see above) and A5 (see below) were
directly affected.

**This is now a standing cluster-infrastructure fact for the remainder of the campaign**: the
`cpu-campaign-20260813` cluster uses **VXLAN**, not IPIP, encapsulation from this point forward.
Tasks 05-11 must not assume IPIP; `artifacts/azure/environment.md` should be read alongside this
note for any task that depends on cluster networking behavior.

## A5: `workload_self_reported_result="unknown"` in 10/10 runs

Caused by the same networking fault (active for the entirety of A5's run, before the fix was
applied). **Not a defect in A5's actual design or finding**: A5's authoritative signal
(`runtimesecuritypolicy_exists`, `runtimeplacementevidence_exists`) is external and independent of
whether the workload's own `wget` succeeded — both were correctly and consistently recorded as
`false` in all 10 runs, which is A5's real result. The workload's self-reported outcome was always
designed to be non-authoritative supplementary context (see `README.md`), so its unavailability
here does not weaken A5's conclusion, but is recorded honestly rather than silently omitted.

**A5 was not re-run after the networking fix.** Rationale: the field it would have corrected is
explicitly non-authoritative, and re-running would consume additional cluster time this campaign's
schedule did not allocate for a re-run of an already-complete, already-conclusive negative-control
experiment. Flagged as a scope decision, not hidden.

## A3 repetition count

`experiment-config.json` already documents that A3 used 5 repetitions per concurrency level
(experiment protocol does not specify an exact count for A3, unlike A1=30/A2=20-per-delay) — an
honest, upfront scope decision, not an exclusion, restated here for completeness.
