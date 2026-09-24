# BPF-LSM enforcement-path microbenchmark

Addresses a specific reviewer concern on the RuntimeGuard paper: the paper's
existing overhead numbers (exec +75.69us, file +2.57us, network +8.95us,
`artifacts/experiments/performance/`) characterize RuntimeGuard's
**observation/audit path** (tracepoint-based — the BPF-LSM enforcement hooks
were never active for that experiment). This directory isolates the
**incremental cost of the BPF-LSM enforcement path specifically**: hook
entry, the workload-policy map lookup, and the complete authorization-derived
enforcement path. Reported and analyzed entirely separately from the
audit-path numbers — never merged or reinterpreted together.

## Environment

Real Azure CPU cluster (same profile as the rest of this campaign, not kind):
Kubernetes v1.30.14, worker `Standard_D2s_v7` (2 vCPU / 8 GiB), Linux
`6.8.0-1064-azure`, containerd, cgroup v2, Calico VXLAN, `cilium/ebpf v0.22.0`,
LLVM/clang 14.x. BPF-LSM confirmed active by checking `"bpf"` is present in
`/sys/kernel/security/lsm` directly (never inferred from `CONFIG_BPF_LSM=y`
alone) — see `environment.txt` and `validation/`.

The `ebpf-agent` DaemonSet runs an image built from this session's additions
to `ebpf-agent/bpf/{common.h,agent.bpf.c}` and `internal/loader/loader.go` —
a `benchmark_mode` field on the existing per-cgroup `cgroup_config` BPF map
entry (`0` = production, unchanged; `1`/`2` = the C1/C2 benchmark conditions
below), plus an opt-in local-filesystem control loop
(`--benchmark-mode-enabled`, false by default) in `cmd/agent/main.go` that
lets this experiment's orchestration detach/reattach one LSM hook or toggle
`benchmark_mode`, via `kubectl exec` into the agent's own pod — never a new
network listener, never touching a real deployment that doesn't explicitly
opt in.

## Commands

```bash
bash reproduce.sh smoke   # 2-block sanity check
bash reproduce.sh full    # the real 30-block-per-operation run
python3 analyze.py        # regenerate paired_results.csv/summary.csv from raw_results.jsonl alone
```

## Experimental conditions

For each of three operation classes (**exec**, **file open**, **network
connect**), exactly four conditions, ALLOW operations only:

- **C0 — Baseline.** The relevant BPF-LSM program is genuinely **not
  attached to the kernel** for this operation (not merely "no policy for
  this cgroup" — a real per-hook `bpf_link` detach/reattach, see
  `internal/loader/loader.go`'s `DetachHook`/`ReattachHook`). Normal
  operation latency with zero BPF-LSM instrumentation in the picture at all.
- **C1 — No-op BPF-LSM.** The hook is attached; it does the mandatory
  per-cgroup config lookup (to even know whether to act) and immediately
  returns ALLOW — no rule-map lookup, no evidence emission.
- **C2 — Map-driven BPF-LSM.** Same hook, now performs the real
  `exec_rules`/`file_rules`/`net_rules` policy-map lookup RuntimeGuard uses
  in production, returning the real ALLOW decision — but still skips
  evidence emission (the ring-buffer write), isolating hook + lookup cost.
- **C3 — Full RuntimeGuard enforcement.** The complete, **unmodified**
  production code path (`benchmark_mode` left at its default `0`) —
  signed D → `derive(D)`=P → worker-side trust validation → Pod UID/cgroup
  binding → active BPF map state → BPF-LSM lookup → ALLOW decision,
  including evidence emission. No new code exists for C3 at all; it is
  literally today's `lsm_exec`/`lsm_file_open`/`lsm_connect`. The signed
  decision authorizing this is minted **once**, before any measurement
  (`scripts/setup.sh`) — the metric is steady-state per-operation latency
  after the policy is already active, not policy-generation/startup latency.

Reused, not rebuilt: `operator/cmd/perf-workload` (the existing N-iteration
timed-loop harness; unmodified), `operator/cmd/mint-test-decision` with this
session's `ExecPolicyRequest`/`FilePolicyRequest`/`NetworkPolicyRequest`
(mint one real signed decision instead of hand-patching a policy — the
worker's trust validation would reject a hand-patched one as tampering, the
same protection this campaign's earlier BPF-LSM correctness diagnostic
already confirmed working). Operation targets match the existing F1
experiment's own defended choices exactly: exec `/bin/true`, file
`/etc/hostname`, network `127.0.0.1:1` (nothing listens there — every
attempt reaches the TCP layer and gets `ECONNREFUSED`, the deterministic,
RTT-free outcome F1 already established; what's timed is the BPF-LSM hook's
own decision path, not a real network round trip).

## Repetitions

30 randomized paired blocks per operation class (90 blocks, 360 individual
measurements total). Within each block, the order of {C1, C2, C3} is freely
randomized (cheap: one local control-channel round trip, no restart). **C0's
position is decided by an independent coin flip** (before or after that
block's C1-3 triplet), not interleaved mid-triplet — the one deliberate
methodological adaptation this experiment makes: C0 requires actually
detaching a BPF-LSM hook (a real, if fast, kernel-level operation), so
interleaving it between every pair of the other three conditions would cost
a second detach/reattach cycle per block for no methodological benefit over
a single cycle per block. `n` per condition (iterations passed to
`perf-workload --n`) reuses F1's own already-validated values for stable
per-op means: exec 2000, file 20000, network 5000.

## Exclusion rules

A block-condition is `excluded=true` (kept in `raw_results.jsonl`, never
silently dropped) when: the `kubectl exec`/control-channel round trip fails
or times out; independent `bpftool` validation (below) does not match the
expected attachment/map state; `perf-workload`'s own JSON output fails to
parse; or (exec/file only) `n_errors > 0` on an ALLOW-authorized operation
(unexpected — network's `n_errors == n` is the intended, documented outcome
above, not an exclusion trigger). `paired_results.csv` skips any block where
one or more of its four conditions was excluded (a partial block cannot
produce a valid paired difference); `analyze.py` computes every summary
number only from non-excluded, complete blocks.

## C0/C1/C2/C3, restated precisely

See `ebpf-agent/bpf/agent.bpf.c`'s `BENCH_MODE_*`-branch comments in
`lsm_exec`/`lsm_file_open`/`lsm_connect` for the exact code each condition
executes. C3 needs no dedicated code — it *is* the unmodified hook.

## Validation performed before accepting each measurement

Independently, via `bpftool` over SSH to the worker (not just trusting the
control-channel's own "OK" acknowledgement): `bpftool link list` confirms
the intended hook is attached (C1-3) or detached (C0); for C2/C3,
`bpftool map dump name cgroup_configs` confirms the bench pod's actual
cgroup entry carries the expected `benchmark_mode` value. Snapshots archived
in `validation/` at the start and end of each operation class's 30-block
run. `/sys/kernel/security/lsm` checked directly once at setup (see
`environment.txt`).

## Known limitations

- Single worker node, single kernel/VM SKU — no claim beyond this exact
  CPU/kernel/testbed configuration (see `manuscript_snippet.md`).
- Network's ALLOW target never completes a real TCP handshake (by design,
  see above) — this isolates BPF-LSM hook cost cleanly but does not
  characterize any RTT-dependent cost a real remote connection would add.
- C0's per-block coin-flip ordering (rather than full interleaving) is a
  disclosed, deliberate adaptation, not an oversight — see Repetitions above.
