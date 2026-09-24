# Experiment B — Observation Completeness (Task 05)

Addresses experiment protocol Q3 (event loss detection), Q4 (alternate-path
bypass), Q5 (silence vs. monitor death), and B4's formal synthesis of
`CompleteObs_Ω(I) ⟺ Coverage_Ω(I) ∧ NoLoss(I) ∧ MonitorLive(I)`.

**Start here**: `summary.md` for the scientific findings and conclusions;
`exclusions.md` for every discarded/invalidated run and the harness bugs
found and fixed along the way (three in B1, one in B2, two in B3 — none
hidden, all documented with root cause and fix).

## Directory layout

- `raw/` — one JSONL file per sub-experiment (`b1-event-loss.jsonl`,
  `b2-altpath-coverage.jsonl`, `b3-monitor-liveness.jsonl`), immutable,
  one JSON record per independent run.
- `discarded-runs/` — every invalidated attempt, retained per experiment protocol
  rule 21 (never silently delete a failed/excluded run), cross-referenced
  from `exclusions.md`.
- `processed/` — CSV summaries generated programmatically from `raw/`.
- `figures/` — plots generated from `processed/`/`raw/`
  (`b1-loss-vs-rate.png`, `b2-altpath-coverage.png`).
- `scripts/` — everything needed to reproduce this experiment:
  - `lib.sh` — shared pod-creation/decision-minting/cleanup helpers.
  - `run-b1.sh`, `run-b2.sh`, `run-b3.sh` — one script per sub-experiment.
  - `rate-gen/`, `altpath-probe/` — Go source for the two custom test
    tools baked into the `observation-tools:task05` image (raw-syscall
    generators, pure stdlib).
- `verifier-output/` — raw `verify-evidence` JSON reports and the
  evidence objects they were run against, for B2/B3.
- `environment.json`, `experiment-config.json` — machine-readable
  provenance (image digests, cluster info, per-sub-experiment parameters).
- `summary.md`, `exclusions.md` — the human-readable writeup.

## Reproducing

Requires a live cluster matching `environment.json` (image digests,
`KUBECONFIG` pointing at `deploy/azure/cpu-campaign-20260813/.run/kubeconfig`)
and the trust-anchor/agent-signing secrets under
`deploy/azure/cpu-campaign-20260813/.run/secrets/`.

```
cd scripts
GATE_START=1 POD_LINGER_SECONDS=120 bash run-b1.sh   # ~5 min
GATE_START=1 bash run-b2.sh                          # ~5 min
bash run-b3.sh                                        # ~3 min (temporarily
                                                        # blocks/unblocks
                                                        # DaemonSet scheduling
                                                        # on the target node,
                                                        # fully reverted)
```

`GATE_START=1` is required for B1/B2 to avoid the closure-gap confound
documented in `exclusions.md` — without it, the scripts still run but the
results are not comparable to what's reported in `summary.md`.
