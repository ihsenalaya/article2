# Phase 6 — Metrics instrumentation on kind: summary

Raw data backing every number below lives in
`results/kind-metrics-20260801T102320Z/` (`propagation_llm-inference.csv`,
`revocation_gpu-workload.csv`, `agent_footprint.csv`, plus the matching
`*.agent-logs.txt` raw log windows used to derive the timestamps). Figures are
computed by `experiments/metrics/analyze_metrics.py` directly from those CSVs
— never typed in by hand. See `EXPERIMENTS_LOG.md` for the full narrative,
including every script bug found and fixed while producing these results.

## Setup

- Same `kind-article2` cluster and 3 workloads as Phase 5, agent in
  audit-only mode (BPF-LSM inactive on this dev kernel).
- Methodology for propagation/revocation: patch-first-then-parse-logs-offline
  (see header comments in `measure_propagation.sh` / `measure_revocation.sh`
  for why a live-polling design was abandoned — real, reproducible race
  against kubectl log latency on this shared, resource-constrained VM, not a
  property of the system under test).
- Footprint: `crictl stats` sampled every 5s for 60s on both kind nodes
  (no metrics-server installed on this cluster; containerd-level stats are a
  direct, real read, not an estimate).

## Results

| Metric | n | min | max | mean | stdev |
|---|---|---|---|---|---|
| Policy propagation time (s) — `llm-inference`, spec change → agent applies | 10 | 0.762 | 4.923 | 2.779 | 1.521 |
| Revocation time (s) — `gpu-workload`, AIPlacementDecision delete → agent revokes | 10 | 2.492 | 4.692 | 3.202 | 0.729 |
| Agent CPU, control-plane node (millicores) | 12 | 0.00 | 7.01 | 1.51 | — |
| Agent CPU, worker node (millicores) | 12 | 0.00 | 12.88 | 6.38 | — |
| Agent memory working set, control-plane (MiB) | 12 | 45.57 | 46.02 | 45.77 | — |
| Agent memory working set, worker (MiB) | 12 | 56.68 | 57.04 | 56.77 | — |

Propagation and revocation both bound above by the agent's 5s poll interval
plus jitter from `sleep 7`/`sleep 8` spacing in the harness — consistent with
a poll-based (not watch-based) reconciliation design, a deliberate
architecture choice documented in `DESIGN.md`. Memory is stable (no growth
across the 60s window sampled); CPU is bursty and low, consistent with a
mostly-idle poll loop plus per-event ring-buffer processing.

## Real script bugs found while building this instrumentation

1. `kubectl annotate` does not bump `.metadata.generation` (only spec changes
   do) — the first propagation-script draft never observed a generation
   change to match against. Switched to patching `spec.bpfLock.enabled`.
2. Live polling (issuing a patch, then polling agent logs in the same loop)
   produced spurious timeouts even though the target log line demonstrably
   existed seconds later on manual inspection — redesigned to
   patch-first-then-parse-logs-offline.
3. `date +%N` yields nanoseconds (9 digits); Python's `strptime("%f")` expects
   microseconds (6 digits) — every timestamp parse silently failed until a
   `sed` truncation was added.
4. The agent's log timestamp field is prefixed `time=...`; the first
   extraction regex assumed no prefix and silently matched empty strings for
   every repetition. Fixed the regex to strip the `time=` prefix.
5. Patches issued faster than the agent's poll interval get coalesced — the
   agent's `List()` only ever observes the *latest* spec at each tick, so an
   intermediate generation can be superseded before ever being logged. This
   is a real, inherent property of poll-based reconciliation, not a bug —
   documented and avoided in the harness (patches spaced 7s apart) rather
   than silently measured as if it were propagation latency.

## Per-hook syscall latency overhead

Data: `hook_latency.csv` (raw), computed by `analyze_metrics.py`.

Method: shell wall-clock timing was tried first and rejected — busybox
`date` on the workload's alpine image silently ignores `%N` (no nanosecond
support), collapsing every measurement to whole seconds, and busybox
`time`'s ~10ms resolution is still far coarser than the effect being
measured. Instead, `measure_hook_latency.sh` + `hook_probe.sh` `nsenter` into
the target container's pid/net/uts/ipc namespaces from the kind node (not
mount, so the node's own `strace`/`bash` stay reachable), write the probe
process's own PID into the container's **real leaf cgroup** (the same one
`bpf_get_current_cgroup_id()` resolves to — see bug #11), and run
`strace -c -f` over a tight loop of the target syscall (300 iterations × 8
repetitions), once with the agent DaemonSet attached and once with it fully
removed (real baseline, not estimated). `strace -c`'s `usecs/call` column is
derived from the kernel's own `wait4()`/`times()` accounting, giving real
microsecond-resolution timing.

**Important caveat**: `strace` itself uses `ptrace`, which adds a large,
constant per-syscall cost common to *both* conditions (native, non-ptraced
syscalls are roughly 1-2 orders of magnitude faster than the absolute
numbers below). Only the **delta between with-agent and without-agent**,
not the absolute `usecs/call` figures, is attributable to the agent —
the ptrace overhead cancels out between conditions since it's identical in
both. The absolute numbers must not be read as native syscall latency.

| Hook | With agent (usecs/call) | Baseline (usecs/call) | Added overhead |
|---|---|---|---|
| execve | n=8, mean=279.0, stdev=31.2 (min 220–max 322) | n=8, mean=226.2, stdev=32.7 (min 187–max 274) | +52.8 usecs/call (+23.3%) — ranges overlap somewhat (noisier than the other two hooks) |
| openat | n=8, mean=81.1, stdev=4.9 (min 76–max 89) | n=8, mean=45.0, stdev=2.6 (min 41–max 48) | +36.1 usecs/call (+80.3%) — conditions cleanly separated, no overlap |
| connect | n=8, mean=160.8, stdev=9.4 (min 148–max 176) | n=8, mean=136.4, stdev=10.7 (min 118–max 148) | +24.4 usecs/call (+17.9%) — conditions cleanly separated, no overlap |

openat and connect show a clean, non-overlapping separation between
conditions; execve shows a consistent mean difference but with some overlap
between per-repetition ranges, i.e. a noisier signal for that hook
specifically — reported honestly rather than smoothed over.

## Tetragon baseline comparison

Deployed Cilium Tetragon v1.7.0 via the official Helm chart
(`cilium/tetragon`), scoped to `article2-worker` only (`nodeSelector`) to
limit footprint on this memory-constrained host, operator/Hubble/export
sidecar disabled, CRDs installed via `crds.installMethod=helm`. A
`TracingPolicy` (`deploy/kind/tetragon-baseline-policy.yaml`) added kprobes
on `sys_execve` and `tcp_connect`, mirroring our own agent's A1/A3
scenarios. Falco was **not** attempted in this pass — deferred, see below.

Real findings, in order of how they were discovered while trying to
reproduce Phase 5's attack scenarios against Tetragon:

1. **`fd_install` (generic file-open) kprobe is unscoped.** A first policy
   also hooked `fd_install` to mirror our A2 (file-open) scenario. Tetragon's
   kprobe selectors filter on Linux namespaces (Uts/Ipc/Mnt/Pid/Net/...), not
   Kubernetes pod/cgroup — confirmed by the API server rejecting a first
   attempt that used `matchNamespaces: workloads` (error message listed the
   supported Linux-namespace values). Left unscoped, `fd_install` fired for
   every `open()` on the entire shared kernel (this WSL2 host runs all kind
   nodes on one kernel), producing ~2000 events in a few seconds of passive
   observation and OOM-killing the Tetragon pod even at a 250Mi memory
   limit. Dropped from the policy for this pass (see policy file header for
   the full note). This is itself a real, useful comparison point: our own
   agent's cgroup lookup (`get_cgroup_config()`) happens *inside* the eBPF
   program before deciding whether to emit anything to userspace, giving it
   a cheap in-kernel early-exit that this naive unscoped kprobe policy
   didn't have.
2. **Kubernetes pod attribution did not resolve for `kubectl exec`-injected
   processes.** Triggering A1 (`kubectl exec llm-inference -- /bin/ls /`)
   and A3 (`kubectl exec llm-inference -- wget ... forbidden-svc`) — the
   exact same injection method used in Phase 5 against our own agent — the
   raw kprobe events fired correctly (right binary path, right destination
   IP/port), but Tetragon's own k8s watcher attributed both to the generic
   node label `article2-worker`, never to `workloads/llm-inference`.
   Reproduced consistently across 3 separate repetitions. By contrast, the
   **same workload's own container-native activity** (its entrypoint
   script's own `cat`/`wget`/`sleep` loop, and `rag-pipeline`'s `curl`/`cat`
   calls) was correctly attributed to `workloads/llm-inference` and
   `workloads/rag-pipeline` respectively when observed passively. We do not
   know the precise root cause (plausibly: Tetragon's process cache tracks
   exec lineage from each container's own tracked init process, and a
   process injected via the CRI `Exec` RPC doesn't descend from that
   tracked lineage the same way) — reporting this as an **observed
   behavior** in this Tetragon version/configuration/kind-containerd stack,
   not as a general claim about Tetragon's capabilities, since the
   underlying cause was not traced into Tetragon's source. Our own agent's
   per-event `bpf_get_current_cgroup_id()` lookup is unaffected by how a
   process was spawned, since it depends only on current cgroup membership,
   not process ancestry — this is a real, defensible architectural
   difference, not a tuning gap we chose not to fix.
3. **Resource footprint** (`crictl stats`, 4 samples over ~20s, policy
   reduced to just the 2 working kprobes): mean ~153 MiB working set, ~35-50
   millicores CPU while mostly idle. Our own agent (Phase 6 footprint
   measurement above, covering *more* hook types — execve, open, connect,
   device) used ~57 MiB on the same node. Not an apples-to-apples
   comparison (Tetragon's 65536-entry process cache and general-purpose
   architecture carry overhead a narrowly-scoped purpose-built agent
   doesn't need), but a real, measured data point.

**Falco baseline: not attempted in this pass.** Given the real findings
above already required significant unplanned debugging (namespace-selector
semantics, CRD install method, OOM from the unscoped file-open hook,
attribution gap), and given the time budget for Phase 6, Falco was
deliberately deferred rather than rushed. Tracked as a follow-up before
Phase 11's related-work comparison is finalized — either revisited later in
this campaign if time allows, or documented as a scope limitation in the
article if not.

## Explicitly NOT measured in this pass (must not be estimated — see rule 1)

- **Formal false-positive/false-negative rate table**: Phase 5 established
  qualitatively that 4/4 real attack scenarios were detected and 1/1
  revocation scenario correctly enforced denial, but no systematic sweep
  (e.g. N legitimate operations × M attack operations, tabulated) has been
  run. Deferred.
- **Falco baseline comparison**: deferred, see above — Tetragon comparison
  completed, Falco not attempted this pass.

## Next action

Phase 6 is closed. Proceed to Phase 7 (Azure IaC). Revisit Falco before
Phase 11's related-work comparison is finalized if time allows.
