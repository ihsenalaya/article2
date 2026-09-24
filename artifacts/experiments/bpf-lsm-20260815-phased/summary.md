# BPF-LSM phased diagnostic — 2026-08-15 session

Experiment protocol: a 6-phase gated protocol to get one
real kernel `EPERM` denial out of BPF-LSM on CPU, kind-first, RuntimeGuard reintroduced
only after the mechanism is proven independently. This directory holds Phases 0-3's
evidence; see the repo's git log / commit messages for Phase 4 onward.

## Phase 0 — code inspection (no modification)

See the session transcript / commit message for the full map of RuntimeGuard's own
hooks, loader, and ALLOW/DENY decision path in `ebpf-agent/bpf/agent.bpf.c` and
`ebpf-agent/internal/{loader,lsmdetect,cgroupmap}`. Not duplicated here since nothing
was changed.

Also found: `artifacts/experiments/bpf-lsm/summary.md` already documents that the PRIOR
CPU campaign (Task 10, Task 12 rounds 1-2, a different Azure VM instance) got real
BPF-LSM active on a comparable Azure kernel but **never** got RuntimeGuard's own DENY
path to produce a real EPERM, under any tested condition. This session does not
contradict that finding (different question: is BPF-LSM itself capable of pre-effect
denial at all on this class of hardware, independent of RuntimeGuard's own code) — see
Phase 4+ for whether RuntimeGuard's own path reproduces cleanly this time.

## Phase 1 — feasibility gate

**kind (this dev machine, WSL2): DECISION GATE B, infeasible.** All kind nodes are
containers sharing the single WSL2 VM kernel. Directly confirmed (not inferred): manually
mounting securityfs inside the running `article2-control-plane` kind container reads
`/sys/kernel/security/lsm` = `capability,landlock,yama,safesetid,selinux` — no `bpf`,
despite `CONFIG_BPF_LSM=y`. `/proc/cmdline` has no `lsm=` parameter and there is no GRUB
on WSL2 (cmdline is set via `.wslconfig` + a full `wsl --shutdown`, a machine-wide,
disruptive change out of scope for a single kind cluster).

**Real Azure CPU VM: DECISION GATE A, feasible.** User chose to provision a fresh
Azure CPU VM pair (reusing `deploy/azure/cpu-campaign-20260813`'s Terraform module,
same `Standard_D2s_v7` / Ubuntu 22.04 / kernel `6.8.0-1064-azure` profile as the prior
campaign). `scripts/enable-bpf-lsm.sh` (already existed from the prior campaign,
encodes the `GRUB_CMDLINE_LINUX` — not `_DEFAULT` — fix for this Azure cloud image)
applied to the worker node. Re-verified directly post-reboot:
`/sys/kernel/security/lsm` = `lockdown,capability,landlock,yama,apparmor,bpf`. See
`raw/phase1-2-environment.txt`.

## Phase 2 — minimal independent BPF-LSM test: PASS

`code/minimal.bpf.c` + `code/minimal-loader-main.go`: a from-scratch `lsm/
bprm_check_security` program with **zero shared code with RuntimeGuard** (only the
same third-party `cilium/ebpf` Go library), hardcoded to deny exactly
`/tmp/runtimeguard-deny-target` and allow everything else. Compiled and loaded
directly on the worker (clang 14 + libbpf-dev + a `vmlinux.h` generated fresh from
that node's own live `/sys/kernel/btf/vmlinux`, not copied from RuntimeGuard's).

Result, single run: ALLOW target exit 0; DENY target — `strace` shows
`execve(...) = -1 EPERM (Operation not permitted)` at the syscall level (see
`raw/phase2-strace-eperm.txt`), and the intended side effect (a marker file the
DENY target would have created if it ran) never occurred.

Repeated (`raw/phase2-10x10-repetitions.txt`): **10/10 ALLOW succeeded, 10/10 DENY
returned EPERM, 0/10 side effects.** Cross-checked against the program's own
hook-invocation counters (`BPF_MAP_TYPE_ARRAY`, dumped via `SIGUSR1`): deny-decision
counter delta across the batch = exactly 10, matching the 10 real DENY attempts with
no spurious or missing denials.

## Phase 3 — map-driven minimal test: PASS

`code/minimal_map.bpf.c` + `code/phase3-loader-main.go`: same hook, hardcoded compare
replaced by a `BPF_MAP_TYPE_HASH` lookup (32-byte zero-padded path key -> `u8`
allow/deny) populated from userspace at load time. Map contents verified via
**independent** `bpftool map dump` (ground truth, not the loader's own self-report)
both immediately after population and again after the test batch — unchanged and
exactly correct both times (`raw/phase3-bpftool-map-dump.txt`).

Result: **10/10 ALLOW succeeded, 10/10 DENY returned EPERM, 0/10 side effects.**
Counters again matched exactly (`deny_decisions=10`, `allow_decisions_mapped=10` for
the batch).

## What this establishes so far

BPF-LSM itself — real kernel hook, real map-driven decision, real pre-effect `-EPERM`
— works cleanly and reproducibly on this specific, freshly-provisioned Azure CPU VM,
using the exact same primitives (LSM `bprm_check_security` hook, `cilium/ebpf` Go
loader, hash-map-driven allow/deny) RuntimeGuard itself uses. This directly answers
the mechanism-level question Phase 2/3 exist to isolate, before RuntimeGuard's own
code is reintroduced in Phase 4. Whether RuntimeGuard's own pipeline (D -> P -> agent
-> cgroup -> map -> LSM) reproduces this cleanly, or reproduces the prior campaign's
unexplained DENY failure, is exactly what Phase 4 tests next.

## Phase 4 — RuntimeGuard end to end: PASS after fixes

The first trusted RuntimeGuard run did reproduce the prior failure, but the cgroup/map
hypothesis was disproved. The application cgroup was `12397` (the pause sandbox was
`12318`), and both cgroups had the `/bin/true` exec allow while the workload was
running. The one-rule postmortem dump was teardown state, not the state at exec time.

The actual failure was hook composition: Linux opens an executable before reaching
`bprm_check_security`, so RuntimeGuard's `file_open` hook applied its independent,
empty, deny-by-default file policy first. The exec allow was therefore never consulted.
`lsm_file_open` now recognizes the kernel's exec-intent bit in `file->f_flags` and
delegates that open to the exec policy path. The BPF-side `bpf_d_path()` length was
also fixed to exclude its trailing NUL, making exact file-rule hashes agree with Go.

The BusyBox test image is dynamically linked, so ordinary loader reads remain subject
to file policy. A signed optional `FilePolicyRequest` now carries the exact runtime
dependency paths independently of the signed `ExecPolicyRequest`; the worker derives
and verifies both before applying them.

Real-kernel run (`raw/phase4-attempt6-final-pass.log`):

- 10/10 `/bin/true` exec ALLOW succeeded;
- 10/10 `/bin/false` exec DENY returned EPERM with no side effect;
- 10/10 `/tmp/allowed-testfile` file ALLOW succeeded;
- 10/10 ordinary `/bin/true` file-open DENY returned EPERM with no side effect.

## Phase 6 — network leg (completed separately): PASS

The prior pass above covered exec and file, matching the protocol's Phase 6
sequencing ("only after exec stable"), but omitted network (`--reps-network=0`). A
`NetworkPolicyRequest` (same additive, signed, mirrored-in-both-modules pattern as
`ExecPolicyRequest`/`FilePolicyRequest`) was added to `pkg/token`, `policy_derivation.go`,
and `trustverify.go`, plus matching `mint-test-decision` flags. Rebuilt/redeployed both
images (`runtime-guard-operator@sha256:96d7653ea05b88f6c6be0a11562427fa24a6335caa2570f5dd18ff7e650b6960`,
`runtime-guard-ebpf-agent@sha256:cfc44b112a64e4c03699c0f25280837928f3d9b76c6fb0a62bf1c6b5f4f61eb0`).

To make DENY a meaningful test (not just "connection refused because nothing was
listening" — the ambiguity the prior campaign's own network test suffered from), real
listeners (`python3 -m http.server`) were started on the worker itself, outside any
enforced pod, on BOTH the allow port (9999) and the deny port (8888). A policy bug would
then show up as an actual successful connection on the deny port, not silence.

Final real-kernel run, all three categories together (`raw/phase4-attempt7-network-complete-pass.log`,
60 individual results): **10/10 exec ALLOW, 10/10 exec DENY→EPERM, 10/10 file ALLOW,
10/10 file DENY→EPERM, 10/10 network ALLOW (real TCP connect succeeded against the live
listener), 10/10 network DENY→EPERM (blocked pre-connection, not merely refused) — zero
side effects on any DENY.** Automated assertion script (embedded in
`code/phase4-runtimeguard-test.sh`) cross-checks the exact signed policy content against
what was actually derived AND against every individual result row, not just a manual read.

The Kubernetes test objects, temporary diagnostic BPF pins, and the two test listeners
were removed after the run. The Azure VMs remain intentionally running. Known follow-up
work includes real CIDR-prefix (not just /32) semantics, removal of stale per-cgroup BPF
rules during policy replacement and cgroup-leaf churn, file permission bits, and
image-digest-bound dependency derivation.
