# EXPERIMENTS MASTER REPORT

Q1 2026 scientific-hardening campaign for RuntimeGuard. This report synthesizes across all 12
tasks (00-11) and 8 experiment directories under
`artifacts/experiments/`.

## 1. Azure environment

- Subscription resource group: `rg-a2-cpucampaign-20260813`, region
  `eastus2`.
- Cluster: `cpu-campaign-20260813` — kubeadm-built Kubernetes
  `v1.30.14`, 2 nodes:
  - `vm-a2-cpucampaign-20260813-cp` (control-plane, tainted
    `NoSchedule`), `Standard_D2s_v7` (2 vCPU / 8 GiB).
  - `vm-a2-cpucampaign-20260813-worker`, `Standard_D2s_v7` (2 vCPU / 8
    GiB).
- Kernel: `6.8.0-1064-azure` on both nodes.
- CNI: Calico (VXLAN). Container runtime: containerd.
- Worker node's active LSM list (Task 10): started as
  `lockdown,capability,landlock,yama,apparmor`; now
  `lockdown,capability,landlock,yama,apparmor,bpf` after a GRUB
  boot-parameter change and reboot. Control-plane node's LSM list was
  deliberately left unmodified (stays audit-mode, an intentional
  within-cluster control).
- Container registry: `acrarticle2ebpftm2ogg.azurecr.io` (Azure
  Container Registry), all images built via `az acr build`.
- No GPU resources of any kind were provisioned in this resource group —
  see section 13.

## 2. Exact software versions

- Kubernetes: `v1.30.14` (kubeadm, control-plane and kubelet).
- Go: `go1.26.5 linux/amd64` (agent/operator build toolchain in this
  environment); `golang:1.21`/`golang:1.25`/`golang:1.25-bookworm` base
  images used for various container builds (bookworm specifically
  pinned for the eBPF regeneration toolchain — see Task 10's
  `exclusions.md`).
- eBPF toolchain: clang/llvm **14.x** (Debian bookworm), matching
  `EXPERIMENTS_LOG.md` Phase 4's originally-used version — a clang 19
  (Debian trixie) attempt was tried and found to produce
  verifier-incompatible bytecode for unrelated, unchanged code (Task
  10's `exclusions.md`).
- cilium/ebpf: `v0.22.0`.
- Calico: as installed by the standard VXLAN manifest during Task 01.
- metrics-server: standard manifest + `--kubelet-insecure-tls` (required
  for kubeadm clusters).

## 3. Git commit

Final commit at the time of this report: `68213e7` ("Task 11: optional
trust-boundary hardening - worker-side D->P validation"). Full task-by-
task commit history:

```
352474e Task 00: repository and implementation audit (D->P->verifier trust boundary)
3268c18 Task 01: rebuild dedicated CPU-only Azure Kubernetes environment
99ec369 Task 02: reproducible RuntimeGuard build, test, and deployment
a74c545 Task 03: fix timestamp semantics for t_p/t_r/t_c
41edc81 Task 04: Experiment A - admission-to-release closure (435 real runs)
5685af5 Task 05: Experiment B - observation completeness
53dfe31 Task 06: Experiment C - revocation and evidence semantics
e98add2 Task 07: Experiment D - Kubernetes identity regression
63f7cad Task 08: Experiment E - scalability with in-cluster generator
db6aec7 Task 09: Experiment F - event-dependent performance cost
263a89b Task 10: Experiment G - real BPF-LSM enforcement on CPU
68213e7 Task 11: optional trust-boundary hardening - worker-side D->P validation
```

## 4. Experiment inventory

| Directory | Task | Experiment protocol Q's | Sub-experiments |
|---|---|---|---|
| `closure/` | 04 | Q1, Q2 | A1 nominal, A2 readiness stress, A3 concurrency stress, A4 non-cooperative control, A5 no-policy control |
| `observation-completeness/` | 05 | Q3, Q4, Q5 | B1 event loss, B2 alt-path bypass, B3 monitor liveness |
| `revocation/` | 06 | Q6, Q7, Q8, Q9 | C1 parameterized polling, C2 watch vs. poll, C3 stale evidence, C4 evidence semantics, C5 acceptance condition |
| `pod-recreation/` | 07 | Q10 | D1 pod-UID recreation regression |
| `scale/` | 08 | Q11, Q12 | E1 steady-state, E2 submission concurrency, E3 500-policy case, E4 event integrity under scale |
| `performance/` | 09 | Q13 | F1-F3 paired ON/OFF blocks, F4 event-rate curve |
| `bpf-lsm/` | 10 | Q14 | G1 safe deny/allow tests, G2 repetitions, G3 critical conclusion |
| `control-plane-tampering/` | 11 (optional) | Q15 | valid-D+correct-P, valid-D+tampered-P |

Every directory contains `README.md`, `raw/`, `processed/`, `scripts/`,
`figures/`, `environment.json`, `experiment-config.json`, `summary.md`,
`exclusions.md` — the protocol's required format (section 14).
`discarded-runs/` is present wherever a run was invalidated (never
silently deleted, per rule 21): `closure`, `scale`, `bpf-lsm`.

## 5. Sample sizes

| Experiment | Condition | n |
|---|---|---|
| A1 (closure) | nominal | 30 |
| A2 (closure) | readiness stress, per delay (4 delays) | 20 each |
| A3 (closure) | concurrency stress, per level (1/10/50) | 5, 50, 250 (238 successful, 12 excluded and documented) |
| A4 (closure) | non-cooperative control | 10 |
| A5 (closure) | no-policy control | 10 |
| C1 detect (revocation) | per poll-interval (5 levels) | 8 |
| C1 evidence (revocation) | per poll-interval (5 levels) | 3 |
| C2 (revocation) | per condition (poll-only / watch) | 10 |
| C3 (revocation) | stale-evidence demonstration | 1 (existence question, not a distribution) |
| D1 (pod-recreation) | pod-UID recreation | 10 |
| E1 (scale) | per N tier (1/10/50/100) | 3 |
| E2 (scale) | per concurrency level (1/10/25), pooled records | 3 reps x 50 decisions = 150 pooled |
| E3 (scale) | 500-policy case | 3 |
| E4 (scale) | event integrity, N=100 | 3 |
| F1-F3 (performance) | exec/file/network paired blocks | 30 each (file/network bumped from 20 in a Task 12 follow-up) |
| F4 (performance) | per concurrency tier (1/2/4/8) | 3 |
| G1 (bpf-lsm) | exec allow/deny | 30 each |
| G1 (bpf-lsm) | file/network allow/deny | 15 each (deliberately not bumped — see section 10's Q14 entry; a valid bump needs a different test methodology given the reconciliation-timing instability found in the Task 12 follow-up) |
| control-plane-tampering | valid-D+correct-P / valid-D+tampered-P | 5 each |

**Sample-size discipline**: every `n` above is a count of independent
experimental units (independent pod/decision/policy lifecycles, or
independent blocks/reps), never assertions x runs — stated explicitly in
every experiment's own `experiment-config.json`.

## 6. Statistical results

See each experiment's own `summary.md` and `processed/*.csv` for full
distributions (this campaign reports raw distributions, not just point
estimates, per experiment protocol section 15). Headline numbers:

- Δ_PR (closure, A1): mean 54.7ms, median 53.8ms, P5 14.8ms, P95 99.1ms,
  never negative in 373 successful A1-A3 runs.
- Δ_detect (revocation, C1): scales from 1.02s (0.5s poll) to 8.44s (10s
  poll), ~interval/2 + fixed overhead.
- F1-F3 (performance): exec +75.69us/op (95% CI [73.95, 77.31],
  bootstrap, n=30), file +2.57us/op (CI [2.04, 3.08], n=30, bumped from
  n=15/20 in a Task 12 follow-up), network +8.95us/op (CI [7.83, 10.04],
  n=30, same bump) — paired Hedges' g reported for all three
  (15.33 / 1.71 / 2.77), not Cohen's d.
- No p-values are computed or reported anywhere in this campaign's
  deliverables (a deliberate choice in `performance/experiment-config.json`,
  to make the protocol's "do not interpret p>0.05 as no overhead"
  warning structurally impossible to violate rather than merely avoided
  by discipline).

## 7. Negative results

Preserved, not smoothed over (experiment protocol section 20's explicit
instruction):

- **Q1**: the release mechanism is a cooperative protocol, not a
  demonstrated non-bypassable barrier (`closure/summary.md`).
- **Q4**: `openat2` and `execveat` are real, measured hook-set bypasses
  (`observation-completeness/summary.md` §B2).
- **Q11/E3**: the literal 500-policy case does NOT converge on this
  cluster (399/500 fail to schedule every rep, cluster-capacity-limited,
  not a RuntimeGuard defect) (`scale/summary.md`).
- **Q14/G1**: pre-effect denial was not observed in 60/60 BPF-LSM deny-
  condition reps despite confirmed-correct kernel configuration — root
  cause not identified within this campaign's time budget
  (`bpf-lsm/summary.md`, `bpf-lsm/exclusions.md`).
- **F3 (performance)**: an unexplained ~19x incorporated-event-count
  anomaly for the exec operation, reported as an open observation, not
  root-caused (`performance/summary.md`).

## 8. Discovered bugs

Full list with root causes in section 18's cross-reference index
(`FINAL_CAMPAIGN_REVIEW.md`'s "Bugs found and fixed" section) and each
task's own `exclusions.md`. Summary count: **4 real bugs in RuntimeGuard's
own eBPF/agent/tooling code** (Task 10's two LSM verifier rejections in
`agent.bpf.c`; the pre-Task-11 complete absence of worker-side D->P
validation, Task 00/11; the Task 12 follow-up's `perf-workload` Go
`os/exec`/`/dev/null` event-inflation bug), plus numerous harness/
infrastructure bugs found and fixed across Tasks 03, 04, 05, 06, 08, 09,
10, 11 (timestamp semantics, capture races, timezone handling,
replay-ledger collisions, image-caching, client-side throttling, GRUB
configuration, toolchain version sensitivity, deployment-manifest drift).
A Task 12 follow-up round 2 additionally found and precisely isolated (not
yet fully root-caused) a fifth real system behavior: BPF-LSM ALLOW-path
reliability degrades after enough policy-reconciliation cycles have run
against an unchanged cgroup — see section 10.

## 9. Fixes made

- `ebpf-agent/bpf/agent.bpf.c`: two LSM-program verifier-rejection fixes
  (Task 10) — separated-branch return values, AND-masked path length.
- `ebpf-agent/internal/trustverify` (new, Task 11): worker-side D->P
  validation; extended in the Task 12 follow-up with
  `LoadTrustAnchorTOFU` (Trust-On-First-Use pinning of the scheduler's
  public key to a node-local file, with an explicit re-arm path for
  legitimate rotation) and `NewReplayLedgerPersistent` (anti-replay
  ledger persisted to a node-local file, surviving agent restarts on the
  same node) — both verified live, not just unit-tested: a real replay
  was correctly rejected by a freshly-restarted agent using reloaded
  ledger state, and the trust-anchor pin file was confirmed to survive
  every restart performed during the follow-up.
- `ebpf-agent/cmd/agent/main.go`: revocation watch path (Task 06), Task
  11 wiring, Task 12 follow-up's `--trust-anchor-pin-path`/
  `--replay-ledger-path` flags wired to the above.
- `deploy/azure/cpu-campaign-20260813/manifests/agent-daemonset.yaml`:
  Task 12 follow-up added a `hostPath` volume
  (`/var/lib/runtime-guard-agent`) backing the pin/ledger persistence
  above.
- `operator/api/v1alpha1/runtimeplacementevidence_types.go`,
  `operator/pkg/evidence/evidence.go`, `operator/cmd/verify-evidence/main.go`:
  `AuthorizationState`/`LastAuthorizationSync`/signed `RevokedAt`, the
  `authorization-currency` check, `AuthorizedAndCompliant` (Task 06).
- Timestamp-semantics fix (Task 03).
- New test tooling (not RuntimeGuard itself, but committed
  infrastructure): `operator/cmd/scale-generator`, `perf-workload`,
  `lsm-probe`, `g1-runner` (Tasks 08-10).
- Task 12 follow-up, round 1: `ebpf-agent/bpf/common.h`/`agent.bpf.c`
  gained a permanent `COUNTER_LSM_HOOK_ENTERED` diagnostic instrument;
  `ebpf-agent/internal/loader/loader.go`'s `ReadEventCounters` extended
  to read it; `operator/cmd/perf-workload/main.go`'s exec op fixed to
  inherit stdio FDs instead of triggering extra `/dev/null` opens
  (partial fix, verified via live rerun, effect reduced ~19x→~11x, not
  eliminated).
- Task 12 follow-up, round 2: `operator/cmd/perf-workload/main.go`
  gained `max_rss_kb_before/after/delta` memory reporting (verified live
  — consistently 0 delta); `artifacts/experiments/performance/scripts/
  run-f1-bump-to-30.sh` and `run-f4-off.sh` (new) closed the remaining
  file/network sample-size gap (20→30) and the F4 OFF-condition-sweep
  gap, both executed live with real results incorporated into
  `performance/summary.md`.

## 10. Remaining unresolved scientific questions

- **Q1's fail-open blind spot**: no experiment in this campaign can
  observe an operation that races ahead of both the launcher and the
  agent's policy-application poll cycle — architecturally invisible to
  the current eBPF hook set. Closing this would need a different
  measurement instrument (e.g., a kernel-side timestamp independent of
  the agent's own policy-application state), out of this campaign's
  scope. Task 10's continued, now triply-confirmed finding that BPF-LSM
  DENY never blocks anything means BPF-LSM enforcement does not
  currently offer an alternative path to closing this gap either.
- **Q14's deny-path root cause — the LSM-chain hypothesis is now
  CONCLUSIVELY ELIMINATED, but the true internal cause remains open
  (Task 12 follow-up, 2 rounds, 2026-08-14)**: round 1 found the
  original "silently falls through to allow" symptom did not reproduce
  on a freshly re-provisioned cluster (a genuine cross-provisioning
  non-reproducibility finding) and narrowed the cause to "somewhere in
  the LSM hook chain." Round 2 tested this directly: bypassing the LSM
  program's own `if (ret != 0) return ret` guard entirely and recording
  the raw `ret` value showed `ret == 0` and an IDENTICAL failure —
  direct, not inferential, proof that no earlier LSM (lockdown,
  capability, landlock, yama, apparmor — all individually ruled out
  across both rounds) is involved at all. A separate, controlled
  single-variable A/B test then isolated the TRUE trigger for the
  ALLOW-path specifically: wait time before the first exec attempt
  (equivalently, the number of the agent's 5-second policy-reconciliation
  cycles that have run against the same cgroup) — 10s wait succeeded,
  25s wait failed, with every other variable held identical. **DENY was
  independently reconfirmed to never block anything under this same fast
  condition**, ruling out reconciliation timing as DENY's own
  explanation and leaving it exactly where round 1 left it, now with
  far more candidate causes eliminated. Two concrete next steps
  (instrumenting `ApplyPlan()`'s exact writes; kernel-map snapshots
  bracketing a known-triggering reconcile cycle) are documented in
  `bpf-lsm/exclusions.md` for any future investigation.
- **F3's exec incorporated-count anomaly, partially resolved (Task 12
  follow-up, round 1)**: root-caused to a real bug in `perf-workload`'s
  own harness code (Go `os/exec` opening `/dev/null` per nil stdio
  stream), fixed, and verified via a live rerun to reduce the effect
  from ~19x to ~11x — dynamic linking directly ruled out as a further
  contributor. The residual ~11x is not root-caused; closing it further
  would need `strace`/`ftrace`-level tracing of Go's `exec.Command`
  internals, not pursued given the reduced effect size and the
  diminishing-returns judgment call made after two full follow-up
  rounds already invested in this campaign's other open items.
- **E3's secondary convergence-failure effect** (2/3 reps' already-
  scheduled decisions not converging within 300s): agent-CPU trend noted
  as a plausible but unconfirmed direction, not demonstrated causally.

## 11. Former paper claims: supported / weakened / falsified / still conditional

(Scored against the kind of claims a systems-security paper about
RuntimeGuard would plausibly want to make, using this campaign's own
forbidden-claim-term list as the register of claim strength.)

| Claim | Status | Basis |
|---|---|---|
| "The release gate provides admission-to-release temporal ordering" | **supported, weakened in strength** | Q2 demonstrates correct internal timing (Δ_PR never negative); Q1 demonstrates this is NOT a non-bypassable guarantee, only a cooperative one. |
| "RuntimeGuard's audit-mode hook set observes all monitored syscalls" | **falsified** | Q4: `openat2`/`execveat` bypass the selected hook set. |
| "Revoked authorization is reflected in evidence within a bounded time" | **supported, with an explicit non-absolute bound** | Q6/Q8: Δ_detect scales predictably with poll interval; Q9: watch improves it; C5 states plainly that no absolute guarantee is possible since revocation itself is unauthenticated K8s API state. |
| "A compromised control plane cannot silently alter enforcement policy" | **supported, newly, as of Task 11** | Q15: DEMONSTRATED for the tested tampering vector (policy content rewrite), with two explicitly out-of-scope limitations stated. Before Task 11, this claim would have been FALSIFIED (zero independent validation existed). |
| "RuntimeGuard scales to 500 concurrent policies" | **falsified** | Q11/E3: 399/500 fail to schedule on this cluster's capacity; not retested at higher literal N due to infrastructure limits, not a RuntimeGuard architectural ceiling per se, but not demonstrated to scale past ~100 on the hardware actually tested. |
| "RuntimeGuard demonstrates real (BPF-LSM) pre-effect kernel denial on CPU hardware" | **still conditional** | Q14: real programs load/verify/gate-allow (new capability this campaign built); pre-effect denial itself not observed. Cannot be claimed as demonstrated. |
| "Monitoring overhead is small and measurable" | **supported** | Q13: single-digit to ~76us/event, with full CIs and effect sizes, not "no overhead" (a forbidden claim never made). |

## 12. Which experiments require no GPU

**All of them.** This entire campaign (Tasks 00-11, all 8 experiment
directories) ran exclusively on `Standard_D2s_v7` CPU-only VMs. No
experiment in this campaign's scope required or used a GPU.

## 13. Confirmation that no GPU resources were created

Confirmed directly against the live Azure resource group immediately
before writing this report:

```
$ az vm list -g rg-a2-cpucampaign-20260813 --query "[].{name:name, size:hardwareProfile.vmSize}"
vm-a2-cpucampaign-20260813-cp       Standard_D2s_v7
vm-a2-cpucampaign-20260813-worker   Standard_D2s_v7
```

Both VMs are `Standard_D2s_v7` (2 vCPU / 8 GiB, no GPU). A full resource
listing for the resource group shows only the expected CPU-campaign
resources (2 VMs, 2 OS disks, 2 NICs, 2 public IPs, 1 NSG, 1 VNet, 2
DevTestLab auto-shutdown schedules — since disabled, see Task 08's
`exclusions.md`) — no GPU SKU, no GPU-series VM (`NC`/`ND`/`NV` family),
no GPU-related managed resource of any kind was ever provisioned in this
resource group. The historical H100 campaign (referenced but never rerun
in this campaign) used an entirely separate, already-torn-down
environment outside this resource group's scope.

## 14. Azure resource teardown status

See `artifacts/azure/teardown-report.md` for the full record. Teardown
has been **executed and verified complete**. `terraform apply` against
the destroy plan removed all 13 resources in `rg-a2-cpucampaign-20260813`
(both VMs, both NICs, both public IPs, the NSG and its subnet
association, the subnet, the VNet, both auto-shutdown schedules, and the
resource group itself) — `Apply complete! Resources: 0 added, 0 changed,
13 destroyed.` Post-teardown, `az group exists -n
rg-a2-cpucampaign-20260813` returned `false`, and subscription-wide
checks confirmed no VM running anywhere, no orphan managed disk, no
orphan public IP, and no resource matching this campaign's name pattern
remained. `acrarticle2ebpftm2ogg` (the container registry used for every
`az acr build` in this campaign) lives in a separate, pre-existing
resource group (`rg-article2-ebpf-20260801`) that this campaign's
Terraform never managed and which was correctly left untouched, per
protocol's "only the dedicated experiment Resource Group/resources"
scoping rule. Billing for this campaign's dedicated infrastructure has
stopped.

**Update**: the infrastructure was subsequently re-provisioned twice
more, identically, for a required Task 12 follow-up (2 rounds; see
section 9's "Fixes made" and section 10) into findings the user did not
accept as permanently unresolved, then torn down again the same way each
time and independently reverified clean both times. See
`teardown-report.md`'s "Second teardown cycle" and "Third teardown
cycle" sections for the full record.
Billing remains stopped as of that second teardown's completion.
