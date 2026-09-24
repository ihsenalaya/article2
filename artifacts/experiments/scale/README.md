# Experiment E — Scalability with In-Cluster Generator (Task 08)

Addresses experiment protocol Q11-ish scalability questions and E1-E4. Discards
the historical WSL2-to-sequential-kubectl 499/500 observation as a
scalability measurement path entirely, per the protocol's explicit
instruction — that number is never reused as evidence of controller
scalability anywhere in this directory.

**Start here**: `summary.md` for findings and conclusions; `exclusions.md`
for every discarded/invalidated run, the four harness bugs found and
fixed along the way, and the mid-task infrastructure incident (VM
auto-shutdown + expired ACR credential) — none hidden, each with root
cause and fix documented.

## Directory layout

- `raw/` — one JSONL file per sub-experiment (`e1-steady-state.jsonl`,
  `e2-concurrency.jsonl`, `e3-500-policy.jsonl`,
  `e4-event-integrity.jsonl`), plus per-run captured generator output
  (`<run_id>.json`), RCA text (E3's `<run_id>.rca.txt`), and evidence
  snapshots (E4's `<run_id>.evidence.json`).
- `discarded-runs/` — every invalidated attempt, retained per experiment protocol
  rule 21, cross-referenced from `exclusions.md`.
- `processed/` — CSV summaries generated programmatically from `raw/` via
  `scripts/analyze.py`.
- `figures/` — plots generated from `processed/`
  (`e1-ready-time-vs-n.png`, `e2-ready-latency-vs-concurrency.png`,
  `e3-convergence-rate.png`, `e4-event-integrity.png`).
- `scripts/` — everything needed to reproduce this experiment:
  - `lib.sh` — shared `run_scale_job`/`cleanup_scale_run` helpers.
  - `rbac.yaml` — ServiceAccount/ClusterRole/ClusterRoleBinding for the
    in-cluster generator.
  - `run-e1.sh`, `run-e2.sh`, `run-e3.sh`, `run-e4.sh` — one script per
    sub-experiment.
  - `analyze.py` — regenerates `processed/` and `figures/` from `raw/`.
- `environment.json`, `experiment-config.json` — machine-readable
  provenance (image digests, cluster info, per-sub-experiment parameters).
- `summary.md`, `exclusions.md` — the human-readable writeup.

## The in-cluster generator

`operator/cmd/scale-generator` (new in this task) is a client-go-based
load generator: bounded-concurrency worker pool, in-process Ed25519
signing (reusing `pkg/token`/`pkg/crypto`, no per-decision subprocess
spawn), a polling-based convergence tracker, and a metrics-sampling
goroutine (`metrics.k8s.io` PodMetricsList for operator+agent CPU/memory).
It runs as a Kubernetes Job (`operator/Dockerfile.scale-generator`),
authenticating via the same `TRUST_ANCHOR_PRIVATE_KEY_HEX` secret the
rest of this campaign uses, and prints exactly one JSON line to stdout on
completion — the run's full per-decision records and metrics samples.

No changes were made to the operator or ebpf-agent binaries for this task
— they remain the Task 06 images.

## Reproducing

Requires a live cluster matching `environment.json`, the trust-anchor
secret under `deploy/azure/cpu-campaign-20260813/.run/secrets/`, and
`scripts/rbac.yaml` applied.

```
cd scripts
bash run-e1.sh   # ~10-15 min (4 N-tiers x 3 reps)
bash run-e2.sh   # ~10 min (3 concurrency levels x 3 reps, N=50 fixed)
bash run-e3.sh   # ~15-20 min (500-policy case x 3 reps + RCA capture)
bash run-e4.sh   # ~10 min (N=100 x 3 reps + evidence-tick wait)
python3 analyze.py
```
