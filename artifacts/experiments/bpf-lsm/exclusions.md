# Exclusions and discarded runs — Experiment G (Task 10)

Per experiment protocol rule 21: failed/invalidated runs are never silently
deleted. This file records every discarded attempt, every real bug found
and fixed along the way, and — most importantly for this task — the one
finding that was NOT resolved, with the full diagnostic trail rather than
a hand-wave.

## Infrastructure: enabling BPF-LSM itself

The first `az vm run-command` attempt (editing `/etc/default/grub`'s
`GRUB_CMDLINE_LINUX_DEFAULT`) was blocked by the harness's own auto-mode
safety classifier, since it was a step toward rebooting the live worker
node. The user was asked explicitly and confirmed before proceeding (a
brief outage of workload pods on that one node was disclosed up front).

After that approval, the FIRST `GRUB_CMDLINE_LINUX_DEFAULT` edit had no
effect on the actual boot: `/etc/default/grub.d/50-cloudimg-settings.cfg`
(an Azure Ubuntu cloud-image file, sourced by `update-grub` AFTER
`/etc/default/grub`) unconditionally sets
`GRUB_CMDLINE_LINUX_DEFAULT=""`, silently discarding anything placed
there. Diagnosed by checking `/proc/cmdline` after the first reboot
(no `lsm=` parameter present at all, and not even `quiet splash`, which
WAS in the edited file — proving something else was overriding it) and
then reading that cloudimg file directly. Fixed by using
`GRUB_CMDLINE_LINUX` instead (which the same cloudimg file APPENDS to,
not overwrites). Second reboot confirmed `bpf` in
`/sys/kernel/security/lsm`.

## eBPF toolchain: three real bugs found and fixed in agent.bpf.c

Once BPF-LSM was active, redeploying the (unchanged) agent image caused
the worker node's agent to crash-loop — the tracepoint-only audit path
this whole campaign had used until now never actually loaded the
`lsm/*` programs, so none of the following had ever been exercised.

**Bug 1 — LSM return-value verifier rejection** (`lsm_exec`,
`lsm_file_open`, `lsm_connect`): the kernel requires an LSM program's
return value to be provably in `[-4095, 0]`. All three functions computed
their `HOOK_MODE_ENFORCE && !allow ? -1 : 0` decision via a ternary/shared
variable; at `-O2`, clang folded this into branchless bit-twiddling
(`AND`/`NEGATE` on the boolean inputs) the verifier could not bound,
rejecting the load with `"R0 has unknown scalar value should have been in
[-4095, 0]"`. Two intermediate fixes were tried and failed:
precomputing the decision before `emit_event()` (still folded the same
way — reproduced identically before AND after that change), and
`barrier_var()` on the precomputed variable (the fold happens while
COMPUTING the ternary, before the barrier is ever reached, so it had no
effect). The fix that worked: two fully separate `if`-blocks, each ending
in its own literal `return -1;` / `return 0;` at the call site, with
`emit_event()` duplicated across both — leaving no single
value-computation site for the compiler to fold.

**Bug 2 — unbounded memory access** (`lsm_file_open` only, discovered
after Bug 1's fix let the verifier reach further into the function): a
different rejection, `"R2 unbounded memory access, use 'var &= const' or
'if (var < const)'"`, on `emit_event`'s `bpf_probe_read_kernel` call —
despite an explicit `if (n > MAX_PATH_LEN-1) n = MAX_PATH_LEN-1;` branch
that sufficed for every other call site (tracepoints, `lsm_exec`,
`lsm_connect`). `lsm_file_open`'s extra `is_device` array-index reads on
`path` between `clamp_len_raw()` and this call evidently cost enough
verifier precision on `path_len`'s tracked bound, crossing the
`emit_event` inline-function boundary, that the branch-derived bound
wasn't provable there. Fixed with an unconditional `path_len &
(MAX_PATH_LEN - 1)` mask (`MAX_PATH_LEN` is a power of 2) — an exact
bound no branch-precision loss can undermine, used uniformly rather than
special-cased.

**Bug 3 — clang version sensitivity** (not agent.bpf.c's fault): the
first regeneration of `internal/bpfobjs/agent_x86_bpfel.{go,o}` used
`golang:1.25`'s default Debian base (trixie → clang 19), which compiled
without any error but produced a DIFFERENT, verifier-rejected bytecode
for `hash_path`'s loop — an existing, unchanged function — with `"invalid
read from stack"`. `EXPERIMENTS_LOG.md` Phase 4 records clang 14.0.0 as
the toolchain originally used for the currently-committed, previously-
working object. Fixed by rebuilding on `golang:1.25-bookworm`
specifically (Debian 12, clang/llvm 14.x) to match. Caught by BOTH cluster
agents crash-looping after that first attempt's rollout — including the
control-plane node's, which had been healthy before and doesn't even run
the LSM programs (its own `mode=audit` — the crash there was Bug 3, not
Bugs 1/2, since it hit the same regenerated object regardless of which
programs actually get attached on that node).

The eBPF regeneration itself required a throwaway multi-stage build
(`ebpf-agent/Dockerfile.gen-bpf`, not used for the final agent image) run
via `az acr build`, since this environment has no local clang/libbpf
toolchain: install clang+llvm+libbpf-dev, `go generate` bpf2go against
`bpf/headers/vmlinux.h` freshly dumped from THIS worker's own live BTF
(`bpftool btf dump`, via `kubectl debug node`), then extract the two
generated files back out of a busybox-based output stage via `kubectl
exec ... cat` (a `scratch`-based output stage was tried first but has no
shell for `kubectl cp`/`kubectl exec` to use at all).

## G1 test harness: real bugs found, one fully fixed, one revealed a deeper platform constraint

**`kubectl exec` itself gets denied once enforce-mode is active with a
restrictive policy** — not a bug in this harness, but a real, load-bearing
discovery that shaped its design: `kubectl exec`'s own OCI runtime attach
path needs to open several `/proc` files inside the container's
namespaces to set up the newly-attached process, and that `open()` is
subject to the SAME `file_open` LSM hook this experiment tests. Under a
deny-by-default policy with only a few narrow allow-list entries,
`kubectl exec` failed with `"open /proc/sys/kernel/cap_last_cap:
operation not permitted"` — for EVERY command, regardless of what the
policy actually allows, since generic `/proc` access was never on any
allow-list. This is itself a small piece of positive evidence that
`file_open` denial is real and reachable (kubectl exec's setup path WAS
denied) — the puzzle documented below is specifically about denying an
explicitly-targeted userspace probe, not about whether denial can ever
fire at all. Forced the harness design to a self-contained runner
(`g1-runner`) that IS the pod's own entrypoint process, since only NEW
process attachment gets denied, not the container's original process.

**Attempt 1 (discarded, `discarded-runs/g1-attempt1-devnull-bug.json`)**:
every condition, including ALLOW, showed EPERM. Root cause: Go's
`os/exec` opens `/dev/null` for any nil `Stdin`/`Stdout`/`Stderr`, and
that open (a device-path file_open) was itself denied under a policy
whose `DeviceAccessPolicy` was never given an allow-list. Fixed by
explicitly setting the probe's `cmd.Stdin/Stdout/Stderr` to the runner's
own already-open (inherited, no new `open()` needed) file descriptors.

**Attempt 2 (discarded, `discarded-runs/g1-attempt2-timing-race.json`)**:
with the /dev/null fix, ALLOW conditions started succeeding correctly,
but this specific run's DENY conditions did not block either. Suspected
a timing race (the harness minted the decision and patched the policy to
enforce-mode in immediate succession, possibly racing the runner's fixed
25s bootstrap-wait).

**Attempt 3 (discarded, `discarded-runs/g1-attempt3-60s-wait.json`)**:
increased bootstrap-wait to 60s, confirmed via agent logs that the policy
had propagated (generation=3) well within that window — yet THIS TIME
even the ALLOW conditions failed (back to the /dev/null-era failure
pattern, `"fork/exec /bin/true: operation not permitted"`), inconsistent
with attempt 2's correct ALLOW behavior at a SHORTER wait. This
inconsistency (2 of 3 real attempts showed correct ALLOW; wait duration
did not predict which) motivated moving to ground-truth kernel inspection
rather than continuing to guess at timing.

**Final retained run (`raw/g1-results.json`)**: used a self-diagnosing
90s warm-up loop (retrying the ALLOW probe every 3s, logged to stderr,
proceeding to the real test suite as soon as it first succeeds) instead
of a fixed wait. ALLOW conditions succeeded reliably (exec 30/30, file
15/15). This is the retained, reported dataset.

## Unresolved: DENY conditions did not block, despite confirmed-correct kernel configuration

In every retained/discarded attempt where the harness itself was not
independently broken (i.e., ALLOW behaved correctly), DENY targets
(`/bin/false`, `/etc/hostname`, `127.0.0.1:8888`) were never observed to
be blocked pre-effect: `/bin/false` executed and exited normally (exit
status 1, its own ordinary behavior, not `EPERM`); `/etc/hostname` opened
and read successfully; the network deny target reached the TCP layer
(`connection refused`, not `EPERM`).

This was investigated with direct kernel-level ground truth, not further
guessing:
- `bpftool map dump` of the live `cgroup_configs` map (host-namespace
  access via `kubectl debug node --profile=sysadmin`, since `kubectl
  exec` cannot be used once enforce-mode is active) confirmed
  `enforcement_mode: 1` (`HOOK_MODE_ENFORCE`) and `exec_default_allow: 0`
  for the test pod's actual cgroup IDs — exactly the correct
  configuration for a deny-by-default policy. A control check against a
  DIFFERENT, deliberately-unpatched pod (left at the operator's default
  `EnforcementMode="audit"`) showed `enforcement_mode: 0` for its own
  cgroups, ruling out "enforcement_mode is hardcoded to 1 regardless of
  policy" as an explanation.
- `bpftool map dump` of `exec_rules` confirmed exactly one entry per
  cgroup, keyed by the hash of `/bin/true` (the only path ever added to
  `AllowedPaths`), with `allow: 1`. No entry exists for `/bin/false`'s
  hash, so a lookup for it must fall through to `exec_default_allow`
  (confirmed 0 above) — by the C source's own logic, this should return
  `-1` (`EPERM`).
- `bpftool prog dump xlated` of the loaded `lsm_exec` program (id 444,
  loaded once at 11:02:36 and never reloaded across all subsequent test
  runs, ruling out stale/inconsistent program instances) was inspected
  instruction-by-instruction around the deny-decision branch; the visible
  logic matches the C source's intent (a `0xffffffff` immediate load at
  the point the deny path's return value is set is consistent with a
  correctly sign-extended 64-bit `-1`, given the verifier's own
  `[-4095, 0]` acceptance of this exact program).
- `dmesg` on the worker node was checked for LSM/audit denial traces
  around the relevant timestamps; nothing relevant was found (the visible
  buffer only contained early-boot messages, likely because it had
  wrapped/been crowded out by other node activity since — inconclusive,
  not evidence either way).

**No further root cause was identified within this task's time budget.**
Candidate hypotheses that were NOT ruled out (documented so a future
investigation doesn't repeat this diagnostic path from scratch):
interaction between the "bpf" LSM and the other active LSMs earlier in
the chain (`lockdown,capability,landlock,yama,apparmor`) at the kernel's
`security_bprm_check()`/hook-chain aggregation level; a possible
verifier-safe-but-semantically-incorrect codegen path not yet located by
manual bytecode inspection (which was not exhaustive — only the region
immediately around the deny branch was examined); or a second call to
`bprm_check_security` (or the equivalent `file_open`/`socket_connect`
hook) within the same operation that this investigation did not know to
look for.

This is reported as an honest, unresolved finding, not smoothed over: see
`summary.md`'s G3 conclusion and `experiment-config.json`'s
`pre_effect_denial_claim` for the resulting, deliberately narrower scope
of what this experiment does and does not establish.

## Task 12 follow-up (2026-08-14): re-investigation, new instrumentation, and a raw-data retention gap in this follow-up itself

The user explicitly did not accept this as a permanently closed,
unresolved finding and required further investigation. The Azure
infrastructure (torn down after the original campaign) was
re-provisioned specifically to continue it. Four live G1 reruns were
performed against the freshly re-provisioned cluster, in this order:

1. **Run 1** — default config (Task 11 worker-trust-validation enabled,
   `agent-daemonset.yaml`'s standard deployment). Result: 120/120 EPERM.
   Root cause found via worker agent logs (`kubectl -n
   runtime-guard-agent-system logs <worker-pod>`, not saved as a raw
   file, but the log line is reproduced verbatim): `"Task 11: worker-side
   D->P validation FAILED, applying safe deny-all plan instead of
   received policy" reason="hash(P_received) != hash(derive(D))..."`.
   This is Task 11 correctly rejecting G1's hand-patched
   `RuntimeSecurityPolicy` as tampering — see `summary.md`'s "Task 12
   follow-up" section for why this is a real, valuable finding about
   G1's methodology, not a bug.
2. **Run 2** — `WORKER_TRUST_VALIDATION=false` (temporarily set via
   `kubectl set env daemonset/runtime-guard-agent`, restored to the
   default afterward), reproducing Task 10's original pre-Task-11 test
   conditions. Result: 120/120 EPERM again, but for a DIFFERENT reason
   this time (confirmed via `bpftool map dump` showing correct kernel
   policy for this run's cgroup IDs, ruling out policy propagation) —
   this is the run that motivated adding the temporary per-event debug
   log described below.
3. **Run 3** — identical to Run 2, but with a temporary debug-level log
   line added to `ebpf-agent/cmd/agent/main.go`'s event handler (`if
   e.Type == 1 && e.HookMode == 1 { slog.Info("TEMP-DEBUG observed exec
   event", ...) }`, since removed — see below), to directly observe
   whether any EXEC ring-buffer event was ever received for this pod's
   cgroup. Result: 120/120 EPERM; **zero** `TEMP-DEBUG` log lines despite
   30 exec attempts each way — the decisive evidence described in
   `summary.md`.
4. **Run 4** (`raw/g1-results-task12-run4-apparmor-unconfined.json`,
   `raw/g1-runner-full-log-task12-run4-apparmor-unconfined.txt`) —
   identical to Run 3, plus the test pod's container explicitly
   annotated `container.apparmor.security.beta.kubernetes.io/g1-runner:
   unconfined`, to directly test and rule out AppArmor. Result: 120/120
   EPERM again, same pattern (all exec/file EPERM, network ALLOW
   correctly `connection refused`) — ruling AppArmor out as the cause.

**Raw-data retention gap in this follow-up (disclosed, not hidden):**
the diagnostic script (`scripts/rerun-g1-diagnostic.sh`) writes its
per-run output to fixed filenames
(`raw/g1-results-task12.json`/`raw/g1-runner-full-log-task12.txt`)
rather than a per-run-unique name. Runs 1-3 overwrote each other's raw
files before being separately archived; only Run 4's raw JSON/log
survived to disk (renamed to
`g1-results-task12-run4-apparmor-unconfined.*` for clarity). This is a
real methodological gap in THIS follow-up's own execution, not present
in the original Task 10 dataset (`g1-results.json`, all 120 original
records, untouched and still intact) — disclosed per the same
rule-21 spirit ("never silently drop data") even though the mechanism
here was an authoring mistake rather than a deliberate exclusion. It
does not undermine the follow-up's conclusions: each run's aggregate
per-op/per-condition success/EPERM counts were computed and recorded
(via `python3 -c "... json.load ..."` inline analysis) immediately after
that run completed and before the next run overwrote its file, and those
aggregate numbers are what `summary.md`'s "Task 12 follow-up" section
reports. `scripts/rerun-g1-diagnostic.sh` is left as-is (documents the
Run 4 / most-recent-run behavior); a future re-run should pass a unique
output-file suffix if per-run raw data must be retained.

**`event_counters` kernel ground truth**: the diagnostic script's
in-script `bpftool map dump name event_counters` capture (piped through
`kubectl debug node ... > file`) silently produced empty output for both
its "before" and "after" attempts — `kubectl debug node`'s non-interactive
attach did not reliably stream command output back through shell
redirection in this environment (confirmed separately: the identical
`bpftool` command run manually, then read back via `kubectl logs
<debug-pod-name>` instead of redirection, worked correctly). The
resulting two empty files were deleted rather than kept as misleading
zero-byte "data". The one successful manual read (Run 1's aftermath,
node-wide, not scoped to a single test's before/after window) showed
`event_counters[3]` (`COUNTER_LSM_HOOK_ENTERED`) at 92771 (cpu0) + 87826
(cpu1) = 180597 cumulative invocations — confirming the hook fires
node-wide (every process's execve, not just tracked cgroups, since the
counter is bumped before the `cfg` lookup) but not usable as a clean
before/after delta for this run specifically, since it was never
captured in the "before" state. This is a genuine capture-method
limitation in this follow-up, not evidence of anything about
RuntimeGuard's own behavior.

**Temporary debug instrumentation, removed**: the per-event debug log
added for Run 3 (`git log` reference: added and reverted within the same
uncommitted working session, never a separate commit) is not present in
the final committed `agent.bpf.c`/`main.go` — only the permanent,
deliberately-retained `COUNTER_LSM_HOOK_ENTERED` instrument (which has
lasting diagnostic value beyond this one investigation) was kept.

**Kernel-log limitations reproduced from the original investigation**:
both `dmesg` (ring buffer, wraps quickly, only contained boot-time
messages when checked minutes into the test window) and `journalctl -k
--since ... -g "apparmor|DENIED|audit"` (empty result for the exact test
window) were tried and found unable to confirm or deny which specific
earlier-in-chain LSM (`lockdown`, `capability`, or `landlock`) is
responsible — the same "audit buffer did not retain the relevant window"
limitation Task 10's original investigation already hit, now confirmed
to persist across two independent kernel-log-access methods, not just
one.

## Task 12 follow-up, round 2 (2026-08-14): full diagnostic trail

The user explicitly required continuing past round 1's state ("candidate
hypotheses narrowed but not confirmed"). Four further tests, in order:

**Test 1 — LSM reorder.** `LSM_LIST="bpf,lockdown,capability,landlock,
yama,apparmor" bash scripts/enable-bpf-lsm.sh` (worker reboot). Actual
post-reboot order, read directly from `/sys/kernel/security/lsm`:
`lockdown,capability,bpf,landlock,yama,apparmor` — the kernel silently
refused to move `bpf` ahead of `lockdown`/`capability`, moving it only
ahead of `landlock`/`yama`/`apparmor`. G1 rerun
(`raw/g1-results-g1-diag-lsm-reorder-14398.json`): identical result to
round 1 (exec/file 100% EPERM both conditions, network correctly
discriminating). Rules out `landlock`/`yama` (already had `apparmor`
from round 1).

**Test 2 — lockdown state.** `kubectl debug node ... -- chroot /host cat
/sys/kernel/security/lockdown` → `[none] integrity confidentiality`.
Lockdown is at its lowest, fully-permissive level. Rules out `lockdown`
as an active cause (it is not restricting anything).

**Test 3 — the decisive ret-bypass test.** `lsm_exec`/`lsm_file_open`
were temporarily edited (git history only, never committed as a real
change — see `agent.bpf.c`'s current, clean state) to:
1. Write the raw `ret` parameter to a new 1-entry `BPF_MAP_TYPE_ARRAY`
   (`diag_last_ret`) as the first instruction.
2. NOT `return ret` when `ret != 0` — always fall through to this
   function's own cfg lookup and decision logic.

Rebuilt (`runtimeguard-bpfgen:task13-diag`,
`runtime-guard-ebpf-agent:cpu-campaign-20260813-task13-diag`), redeployed,
reran G1 (`raw/g1-results-g1-diag-ret-bypass-29535.json`): IDENTICAL
result (exec/file 100% EPERM both conditions). `bpftool map dump name
diag_last_ret` read `{"key": 0, "value": 0}` — `ret` was 0. This is
direct proof, not inference: no earlier LSM was denying anything, and
bypassing the `ret != 0` guard changed nothing, because there was
nothing to bypass. **The entire "earlier LSM in the chain" hypothesis
from round 1 — the leading candidate at the time — is conclusively
false.**

**Test 4 — isolating reconciliation timing.** With the ret-bypass build
still deployed, a second temporary debug log
(`TEMP-DIAG2 observed exec event`, logging every `EVENT_TYPE_EXEC`
ring-buffer event's path/decision — meaningful now because the bypass
build reaches `emit_event()` unconditionally) was added, rebuilt as
`runtime-guard-ebpf-agent:cpu-campaign-20260813-task13-diag2`, and used
for a series of manually-orchestrated (not `rerun-g1-diagnostic.sh`)
minimal tests, isolating one variable at a time:

- Minimal test A (`bootstrap-wait=10s`, `reps-exec=2`,
  `reps-file=0`, `reps-network=0`, exec-only policy patch): **SUCCEEDED**
  — `/bin/true` executed cleanly (`success=true`) on both reps, the
  first time in this entire follow-up that ALLOW worked. (`/bin/false`
  still was not blocked — `raw_error="exit status 1"`, i.e. it executed
  and exited with its own normal code, not `EPERM`.)
- Minimal test B (identical to A, only `bootstrap-wait` changed to
  `25s`): **FAILED** — 100% EPERM on both allow and deny, matching every
  other slower test in this investigation.
- Full-scale exec-only-patch test (`/tmp/rerun-g1-exec-only.sh`, the
  standard 25s wait / 30-rep methodology, but with ONLY the `exec` field
  patched, no `fileAccess`/`networkEgress`): **FAILED** identically
  (`raw/g1-results-g1-diag-run-5399.json`), ruling out "which policy
  fields get patched" as the variable (round 1 had not yet ruled this
  out).

Test A vs. B, identical in every other respect, isolates the causal
variable to **wait time before the first exec attempt** — equivalently,
the number of the agent's 5-second policy-reconciliation cycles
(`--poll-interval=5s`) that have run against the SAME cgroup before that
attempt. `ApplyPlan()` (`ebpf-agent/internal/loader/loader.go`) writes
`cgroup_configs` first, then `exec_rules`/`file_rules`/`net_rules` in a
loop, on EVERY reconcile cycle regardless of whether the plan changed
(confirmed via agent logs: `"applied policy" ... generation=2` then
`generation=3`, 5 seconds apart, for an unchanged policy) — a plausible,
but NOT further confirmed, mechanism is that repeated re-application to
an already-correct cgroup corrupts a kernel-side lookup structure in a
way a static `bpftool map dump` (taken after the fact) does not reveal.
This was not decomposed further within this round's time budget.

**Two concrete next steps, for any future investigation** (documented so
it does not have to rediscover this trail):
1. Instrument `ApplyPlan()` to log the exact key/value of every
   `Put()` call, and check whether the SET of cgroup IDs resolved for a
   given pod changes between the first and a later reconcile cycle (a
   plausible mechanism: containerd/runc reorganizing a container's
   cgroup shortly after startup, so the agent's second application
   writes correct rules to a cgroup ID the process is no longer, or not
   yet, actually running in).
2. If (1) is ruled out, use `bpftool map dump` taken IMMEDIATELY before
   and after a reconcile cycle that is known (from a prior fast-vs-slow
   test) to trigger the failure, to check whether the map's content
   itself changes between cycles for the same cgroup ID (as opposed to
   the currently-confirmed "eventually correct, but exec still fails"
   state).

Neither the temporary `ret`-bypass/`diag_last_ret` code nor the second
`TEMP-DIAG2` Go log were committed — `agent.bpf.c`/`cmd/agent/main.go`
were restored to their clean, committed state (verified via `git diff`
showing no changes) before this follow-up's real deliverables
(TOFU pinning, ledger persistence, memory metric, F1/F4 additions) were
built and deployed. Only the permanent `COUNTER_LSM_HOOK_ENTERED`
instrument from round 1 remains.

## Note: automated `bpftool_dump_map` capture still unreliable in this harness

`rerun-g1-diagnostic.sh`'s fixed `bpftool_dump_map` helper (which parses
the debug pod name from `kubectl debug node`'s own stderr, then reads it
back via `kubectl logs`) still produced empty (`{}`) `event_counters_*`
files across every round-2 rerun — the debug-pod-name parsing did not
reliably match in this automated, non-interactive context, the same
underlying `kubectl debug node` unreliability documented in round 1,
now confirmed to persist even after the redesign. The empty placeholder
files were deleted (not retained as misleading zero-byte "data"). The
actual `event_counters`/`diag_last_ret` values referenced in `summary.md`
(node-wide `COUNTER_LSM_HOOK_ENTERED=180597`; `diag_last_ret=0`) were
obtained via manual, interactive `kubectl debug node -it` + direct
`kubectl logs <known-pod-name>` invocations during this session, not via
this script — the exact commands are reproduced in `summary.md`'s
round 1/round 2 sections. A fully reliable automated capture would need
a different mechanism (e.g. a short-lived privileged Job with a
predictable, fixed name, or a `bpftool`-capable static binary copied
onto the node directly) — not built here, since the manual method
already provided the needed evidence.
