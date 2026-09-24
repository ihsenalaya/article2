# Experiment A — Admission-to-Release Closure (Task 04)

Replaces the previous misleading "40/40" presentation. Measures:

    Δ_PR = t_r - t_p   (policy-ready → release)
    Δ_RC = t_c - t_r   (release → first externally-observed critical operation)

using the fixed timestamp instrumentation from Task 03 (`RuntimeSecurityPolicy.Status.
EnforcementReadyMonotonicNs` for t_p, the launcher's own `CLOCK_MONOTONIC_RAW` reading for t_r,
`Status.FirstObservedOperationMonotonicNs` — a real eBPF observation — for t_c). The independent
sample size is the number of runs (pod lifecycles), never assertions × runs.

## Structure

- `raw/` — one JSONL file per condition group, one line per independent run. Immutable.
- `processed/` — `closure-summary-stats.csv`, generated programmatically by `scripts/analyze.py`
  from `raw/` only (rule 25/26: no manual editing of statistical results).
- `scripts/` — `lib.sh` (shared trial mechanics), `run-a1.sh` .. `run-a5.sh` (orchestration),
  `analyze.py` (stats + figures), `00-setup.sh` (one-time RBAC/target-service setup).
- `figures/` — generated PNGs (boxplots of Δ_PR/Δ_RC by condition).
- `environment.json`, `experiment-config.json` — exact software/config used.
- `summary.md` — narrative results and answers to Q1/Q2.
- `exclusions.md` — every excluded/failed run, retained and explained, never silently dropped.

## Trial mechanics (A1/A2/A3 — cooperative conditions)

Each trial creates a real Kubernetes pod with:
- an `initContainer` running the actual `runtime-guard-launcher` binary (not a simulation),
  polling `RuntimeSecurityPolicy.Status` and writing a shared ready-file once
  `EnforcementReady` is observed;
- a `workload` container that busy-waits (20ms granularity) on that ready-file, then performs a
  real TCP connect (`wget`) to a target Service — the "critical operation," externally observed
  by the eBPF agent via the `socket_connect`/`connect` hook path.

A fresh, correctly Ed25519-signed `AIPlacementDecision` (via `operator/cmd/mint-test-decision`,
the same tool used in Task 00-03's live verification) is minted and applied for each run, bound
to that specific pod's real UID and node — exercising the real D→P→agent→eBPF pipeline
end-to-end, not a mock.

t_p and t_c are read directly from the live `RuntimeSecurityPolicy.Status` after the trial (agent-
authoritative); t_r comes from the launcher's own stdout JSON (its own `CLOCK_MONOTONIC_RAW`
reading, captured immediately after it observed readiness). All three run on the same node.

## A2's delay mechanism

A2 requires "artificially delaying policy readiness." This is implemented as a new, opt-in,
per-pod-annotation test-harness hook in `ebpf-agent/cmd/agent/main.go` (`reconcileOnce`):
`experiment.article2.io/inject-ready-delay-ms` on the target pod causes the agent to
`time.Sleep` that duration before its *first* policy application for that specific pod only —
zero effect on any pod without the annotation, and only applied once (not every poll cycle).
See `artifacts/reviews/TASK_04_REVIEW.md` for why this belongs to Task 04 (test-harness
instrumentation, experiment protocol rule 2) rather than reopening the already-completed Task 03.

## A4 — non-cooperative workload (mandatory)

No `initContainer`, no wait logic of any kind. The workload attempts its critical operation
(TCP connect) the instant its process starts. A real signed decision/policy is still created (so
t_p is real and comparable), but the workload never checks it. This directly tests Q1: is the
release mechanism a non-bypassable barrier, or a cooperative protocol that a non-cooperative
workload can simply ignore?

## A5 — no-policy negative control

No decision, no policy, ever. Observation is checked externally (existence of
`RuntimeSecurityPolicy`/`RuntimePlacementEvidence` objects for the pod), not from the workload's
own self-reported log — directly testing whether the system can tell the difference between "no
attempt" and "unobserved attempt."

## Reproduce

```
export KUBECONFIG=deploy/azure/cpu-campaign-20260813/.run/kubeconfig
cd artifacts/experiments/closure/scripts
./00-setup.sh
./run-a1.sh 30
./run-a2.sh 20
./run-a3.sh 5
./run-a4.sh 10
./run-a5.sh 10
python3 analyze.py
```
