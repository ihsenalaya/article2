# Experiment F — Event-Dependent Performance Cost (Task 09)

Addresses experiment protocol Q13 (RuntimeGuard overhead as a function of event
volume) and F1-F5. This is the new primary CPU-based, event-centric
performance experiment; the old H100 GPU-inference ON/OFF results remain
historical/exploratory only and are neither rerun nor cited as evidence
here.

**Start here**: `summary.md` for findings and conclusions; `exclusions.md`
for the one interruption this task hit (an environment/session restart
mid-sweep) and exactly what it did and did not affect — no data was lost
or discarded.

## Directory layout

- `raw/` — `f1-paired-blocks.jsonl` (70 paired ON/OFF blocks across three
  operation types), `f3-event-drop-check.jsonl` (3 records, one per op
  type), `f4-rate-curve.jsonl` (12 records, 4 concurrency tiers x 3 reps).
- `processed/` — CSV summaries generated programmatically from `raw/` via
  `scripts/analyze.py`, including paired-differences statistics.
- `figures/` — `f1-paired-diff-by-op.png` (mean incremental cost per op
  with bootstrap 95% CI), `f1-paired-diff-distributions.png` (per-block
  difference histograms), `f4-rate-curve.png` (achieved throughput and
  CPU cost vs. concurrency).
- `scripts/` — everything needed to reproduce this experiment:
  - `lib.sh` — shared ON/OFF pod-creation, workload-exec, and evidence-
    query helpers (documents the ON/OFF semantics in its header comment,
    derived from direct `agent.bpf.c` code inspection).
  - `run-f1.sh` — F1-F3 paired blocks + F3 event/drop check.
  - `run-f1-resume.sh` — resumes an interrupted `run-f1.sh` run without
    discarding already-collected data (see `exclusions.md`).
  - `run-f4.sh` — F4 concurrency/rate curve.
  - `analyze.py` — regenerates `processed/` and `figures/` from `raw/`.
- `environment.json`, `experiment-config.json` — machine-readable
  provenance (image digests, ON/OFF semantics, per-sub-experiment
  parameters, statistics methodology).
- `summary.md`, `exclusions.md` — the human-readable writeup.

## The workload generator and ON/OFF mechanism

`operator/cmd/perf-workload` (new in this task) is a small, pure-stdlib
Go binary with no Kubernetes API dependency: given `--op` (exec/file/
network) and `--n`, it runs that many iterations of the operation and
reports precise wall-clock and CPU-time cost (via `getrusage`) as a single
JSON line. It runs inside a long-lived pod (`operator/Dockerfile.perf-workload`,
busybox-based so `/bin/true` exists for the exec operation); the actual
timed run is invoked on demand via `kubectl exec`.

ON vs OFF is controlled entirely by the harness, not by this binary: an
ON pod additionally has a real, signed `AIPlacementDecision` minted and
applied for it (reusing `operator/cmd/mint-test-decision`, the same
pattern as the revocation experiment), giving its cgroup an entry in the
agent's eBPF `cgroup_configs` map; an OFF pod never gets one. Confirmed by
direct inspection of `ebpf-agent/bpf/agent.bpf.c`: every tracepoint
handler does `if (!get_cgroup_config(cgroup_id)) return 0` before any
further work, so this measures RuntimeGuard's genuine per-event marginal
cost, not merely whether the agent process is running.

## Reproducing

Requires a live cluster matching `environment.json`, the trust-anchor
secret under `deploy/azure/cpu-campaign-20260813/.run/secrets/`.

```
cd scripts
bash run-f1.sh    # ~35-40 min (70 paired blocks + F3 check)
bash run-f4.sh    # ~10 min (4 concurrency tiers x 3 reps)
python3 analyze.py
```
