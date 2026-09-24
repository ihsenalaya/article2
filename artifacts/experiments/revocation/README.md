# Experiment C — Revocation and Evidence Semantics (Task 06)

Addresses experiment protocol Q6 (evidence between revocation and worker
awareness), Q7 (can valid evidence remain semantically stale), Q8
(revocation latency vs. polling period), Q9 (does watch improve it), Q10
(N/A here — Kubernetes identity regression is Task 07), and C1-C5.

**Start here**: `summary.md` for findings and conclusions; `exclusions.md`
for every discarded/invalidated run and the four harness bugs found and
fixed along the way (two in C1, one in C2, one in C3 — none hidden, each
with root cause and fix documented).

## Directory layout

- `raw/` — one or two JSONL files per sub-experiment
  (`c1-detect-latency.jsonl`, `c1-evidence-latency.jsonl`,
  `c2-watch-vs-poll.jsonl`, `c3-stale-evidence.jsonl`), immutable, one JSON
  record per independent run.
- `discarded-runs/` — every invalidated attempt, retained per experiment protocol
  rule 21, cross-referenced from `exclusions.md`.
- `processed/` — CSV summaries generated programmatically from `raw/` via
  `scripts/analyze.py`.
- `figures/` — plots generated from `processed/`
  (`c1-detect-latency-vs-poll-interval.png`,
  `c1-evidence-latency-vs-poll-interval.png`, `c2-watch-vs-poll.png`).
- `scripts/` — everything needed to reproduce this experiment:
  - `lib.sh` — shared pod-creation/authorization/poll-interval-and-watch-toggling helpers.
  - `run-c1.sh`, `run-c2.sh`, `run-c3.sh` — one script per sub-experiment.
  - `analyze.py` — regenerates `processed/` and `figures/` from `raw/`.
- `verifier-output/` — raw `verify-evidence` JSON reports and the captured
  evidence/policy YAML they were run against, for C3.
- `environment.json`, `experiment-config.json` — machine-readable
  provenance (image digests, cluster info, per-sub-experiment parameters).
- `summary.md`, `exclusions.md` — the human-readable writeup.

## Key implementation changes this experiment depends on

- `ebpf-agent/cmd/agent/main.go`: opt-in Kubernetes watch-based revocation
  path (`--watch-revocation`/`WATCH_REVOCATION`, `watchRevocationLoop`),
  sharing the same revoke action (`revokeTrackedPolicyLocked`) as the
  pre-existing poll-based path.
- `operator/api/v1alpha1/runtimeplacementevidence_types.go`,
  `operator/pkg/evidence/evidence.go`: `AuthorizationState` and
  `LastAuthorizationSync` added to the **signed** payload; `RevokedAt`
  moved from status-only/unsigned into the signed payload.
- `operator/cmd/verify-evidence/main.go`: new `--max-authorization-age`
  flag, `authorization-currency`/`authorization-state-present` checks, and
  a top-level `authorized_and_compliant` field deliberately reported
  separately from `valid`.

## Reproducing

Requires a live cluster matching `environment.json` and the trust-anchor/
agent-signing secrets under
`deploy/azure/cpu-campaign-20260813/.run/secrets/`.

```
cd scripts
bash run-c1.sh   # ~55 min (5 poll-interval conditions x fast+slow loops)
bash run-c2.sh   # ~13 min (poll-only + watch-enabled, 10 reps each)
bash run-c3.sh   # ~2.5 min (single trial)
python3 analyze.py
```

`run-c1.sh` and `run-c2.sh` patch the live `runtime-guard-agent` DaemonSet
(`--poll-interval`, `WATCH_REVOCATION`) as part of the experiment; both
restore production defaults (`WATCH_REVOCATION=false`) when they finish.
