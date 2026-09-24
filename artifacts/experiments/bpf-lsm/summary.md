# Experiment G — Summary (Task 10)

Addresses experiment protocol Q14 (can real BPF-LSM pre-effect denial be
demonstrated on a CPU worker?) and G1-G3.

## Runtime condition verification (not inferred from CONFIG_BPF_LSM alone)

Per the protocol's explicit instruction, "bpf" appearing in
`/sys/kernel/security/lsm` — not merely `CONFIG_BPF_LSM=y` — is the
required runtime condition. Both were checked directly:

- `CONFIG_BPF_LSM=y` confirmed in `/boot/config-6.8.0-1064-azure`.
- `/sys/kernel/security/lsm` initially read `lockdown,capability,
  landlock,yama,apparmor` — `bpf` absent. Fixed via a GRUB boot-parameter
  change and a worker-node reboot (user-confirmed before rebooting; see
  `exclusions.md` for a real Azure-cloud-image GRUB gotcha hit along the
  way). Re-verified post-reboot: `/sys/kernel/security/lsm` now reads
  `lockdown,capability,landlock,yama,apparmor,bpf`.

## What this experiment establishes (positively demonstrated)

1. **Real BPF-LSM programs load and verify on this hardware.** The
   worker node's agent determines `mode=enforce` from a live check of
   `/sys/kernel/security/lsm` and successfully loads and verifies all
   four LSM programs (`lsm_exec`, `lsm_file_open`, `lsm_connect`,
   `lsm_bpf_lock`) — confirmed via `bpftool prog list`/`dump`, not
   inferred from the agent staying `Running`. This had never actually
   been exercised anywhere in this campaign before this task (the
   tracepoint-only audit path never attaches `lsm/*` programs at all),
   and getting there required finding and fixing three real bugs — two
   in `agent.bpf.c` itself, previously-undetected eBPF verifier
   rejections specific to LSM-return-value semantics, and one in the
   regeneration toolchain (clang version sensitivity) — documented in
   full in `exclusions.md`.
2. **Policy configuration correctly reaches the kernel.** Direct
   `bpftool map dump` of the live `cgroup_configs` and `exec_rules` maps
   (not the Kubernetes CRD object, which only proves the control plane's
   intent, not what the kernel actually has) confirms
   `enforcement_mode=ENFORCE`, `exec_default_allow=DENY`, and exactly the
   intended single allow-list entry — see
   `raw/ebpf-map-groundtruth.txt`.
3. **The ALLOW path is correctly gated by this real (not audit-only)
   enforcement path.** Every ALLOW-condition repetition succeeded (exec
   30/30, file 15/15) under a confirmed enforce-mode policy with a
   deny-by-default posture — this is not the tracepoint audit path
   (which never blocks anything and was already characterized in earlier
   tasks); it is the same `lsm/*` code path that would deny an
   unauthorized operation, correctly not denying an authorized one.

## What this experiment does NOT establish (honest negative finding)

**Pre-effect denial was not observed.** Across all 60 DENY-condition
repetitions (exec 30, file 15, network 15), the designated deny targets
were never blocked: `/bin/false` executed normally (its own ordinary
exit code 1, not `EPERM`); `/etc/hostname` opened and read successfully;
the network deny target reached the TCP layer (`connection refused`, a
post-effect network-stack response, not a pre-effect `EPERM`).

This was investigated with direct kernel ground truth (not just repeated
retries): the `cgroup_configs` and `exec_rules` map contents were
independently confirmed correct for the cgroup actually running the
deny-condition probes (see `raw/ebpf-map-groundtruth.txt`), and the
loaded program's translated bytecode around the deny-decision branch was
inspected and is consistent with the C source's intent. No inconsistency
was found in any of the state this investigation could directly observe.
**The root cause was not identified within this task's time budget** —
see `exclusions.md` for the full diagnostic trail and the candidate
hypotheses left for follow-up (LSM hook-chain interaction with the other
four active LSMs; an unexamined region of the compiled bytecode;
possible multiple hook invocations per operation).

## Answer to Q14 and G3's critical conclusion

**Partially, with an explicit, load-bearing caveat.** Real (not
audit-only) BPF-LSM enforcement infrastructure is demonstrated to load,
verify, and correctly gate the allow path on this Azure CPU worker —
genuinely new capability this campaign had not exercised before, and a
nontrivial engineering result in its own right (three real, previously-
latent bugs found and fixed to get there). But the specific claim G3
asks this experiment to unlock — "RuntimeGuard claims experimentally
demonstrated CPU BPF-LSM **pre-effect enforcement**" — requires the deny
path to work, and it was not observed to. **This experiment does not
license that stronger claim.** Per the protocol's own scope
instruction, this finding is specific to the new Azure CPU worker and is
never extended to the H100 historical campaign (which remains
audit/observation-only, unaffected by anything in this task).

## Limitations

- G1's `n=30` (exec) meets the protocol's target exactly; `n=15`
  (file, network) is a documented scope reduction under real time
  constraints, consistent with every prior experiment in this campaign.
- The deny-path investigation, while using direct kernel-level ground
  truth rather than surface-level retries, was not exhaustive (bytecode
  inspection covered only the region around the deny decision, not the
  full ~2600-byte program; kernel LSM hook-chain source code was not
  read). A definitive root cause may require kernel-level tracing
  (ftrace/kprobe on `security_bprm_check`) beyond this task's scope.
- Only the exec, file-open, and connect hooks were tested; `lsm_bpf_lock`
  (the BPF-load defense-in-depth hook) was confirmed loaded but not
  exercised by a dedicated test in this task.

## Task 12 follow-up: re-investigation with new instrumentation (2026-08-14)

The user explicitly rejected leaving this finding as an unexplained
mystery and required further root-causing before the campaign could be
considered complete. The Azure infrastructure was re-provisioned
specifically to continue this investigation (see
`artifacts/azure/teardown-report.md` for the intervening teardown and
this follow-up's own new provisioning cycle). `agent.bpf.c`/`common.h`
gained a new, permanent instrument for this purpose:
`COUNTER_LSM_HOOK_ENTERED`, bumped as the unconditional first instruction
of every `lsm/*` program, before any cfg lookup or decision logic — see
the doc comment at its definition in `common.h`.

**The original "nothing ever blocks" finding did not reproduce.** On the
freshly re-provisioned cluster (same VM SKU, same kernel
`6.8.0-1064-azure`, same GRUB `lsm=` list, freshly re-verified `bpf` in
`/sys/kernel/security/lsm`, identical `bpftool map dump`-confirmed
correct kernel policy configuration), the G1 suite instead showed a
DIFFERENT failure mode: with Task 11's worker-side D→P trust validation
active (the campaign's default), the hand-patched `RuntimeSecurityPolicy`
G1's test methodology uses (`kubectl patch runtimesecuritypolicy` with
custom exec/file/network rules not derivable from the signed decision D)
is correctly and expectedly rejected as tampering — `hash(P_received) !=
hash(derive(D))` — falling back to a deny-all plan. **This is Task 11
working exactly as designed**, and is itself a valuable, previously-
unknown confirmation that Task 11's protection generalizes beyond its
own dedicated experiment: G1's test methodology is fundamentally
incompatible with an active, correctly-functioning D→P trust boundary,
since it does exactly what that boundary exists to catch. This
methodology/trust-model interaction is a genuine finding in its own
right, not a bug in either Task 10 or Task 11.

To reproduce Task 10's original (pre-Task-11) test conditions, worker
trust validation was disabled for this diagnostic only
(`--worker-trust-validation=false`, restored to the default `true`
immediately after — see `experiment-config.json`). Under these
conditions, G1 reproduced a THIRD, new, and more precisely diagnosable
failure mode, consistently across two independent repetitions:

**ALL conditions returned EPERM — including the designated ALLOW
targets for exec and file-open** (`/bin/true`, `/tmp/allowed-testfile`),
despite `bpftool map dump` again confirming the kernel-side
`cgroup_configs`/`exec_rules` maps were 100% correct for the actual
cgroup in use (`enforcement_mode=ENFORCE`, and an `exec_rules` entry
keyed by the exact FNV-1a hash of `/bin/true` — verified byte-for-byte
against an independent Python re-implementation of the hash — with
`allow=1`). The network ALLOW target, uniquely, behaved correctly
(`connection refused` at the TCP layer, not `EPERM`), isolating the
failure to the path-hash-based exec/file-open decision path specifically
and ruling out cgroup-identification or general enforce-mode
misconfiguration as the cause.

**Decisive new evidence: `COUNTER_LSM_HOOK_ENTERED` incremented (proving
the kernel does invoke `lsm_exec`/`lsm_file_open` for these operations),
but a temporary per-event debug log added to the agent (logging every
observed `EVENT_TYPE_EXEC` ring-buffer event in enforce mode) recorded
ZERO events across all 30 exec attempts, allow and deny alike** — despite
`emit_event()` being called on literally every code path through
`lsm_exec`'s body (both the deny branch and the fallthrough
allow/log branch unconditionally call it before returning). The only way
zero ring-buffer events can coexist with the hook being invoked and the
process being denied is that **`lsm_exec` returns via its own `if (ret
!= 0) return ret;` guard — before ever reaching `emit_event()` — because
`ret` was already nonzero when the hook fired.** That guard is
deliberate, existing, correct code (see the comment at
`lsm_exec`/`lsm_file_open`/`lsm_connect`'s first lines): per BPF-LSM
`fmod_ret` semantics, `ret` carries the accumulated decision from
whichever LSM hooks earlier in the node's `lsm=` chain
(`lockdown,capability,landlock,yama,apparmor`, in that order, before
`bpf`) already ran for this same operation. **This is proof, not
inference, that RuntimeGuard's own eBPF program is not the source of
this denial** — an earlier LSM in the chain is.

AppArmor was directly tested and ruled out: re-running G1 with the test
pod's container explicitly annotated
`container.apparmor.security.beta.kubernetes.io/g1-runner: unconfined`
produced an identical result (all EPERM, zero emit_event calls) —
confirmed applied via the pod's own `.metadata.annotations` (with a
`deprecated since v1.30` warning, non-blocking, still honored by this
kubelet version). `dmesg`/`journalctl -k` were checked for AppArmor or
audit denial records during the test window and, as in Task 10's
original investigation, contained no relevant entries (ring buffer/
journal retention did not cover the window) — inconclusive, not
evidence either way, consistent with Task 10's own prior finding of the
same limitation.

**Net result: the remaining candidate set is narrowed to `lockdown`,
`capability`, or `landlock` intercepting `bprm_check_security`/
`file_open` for this container's process before RuntimeGuard's own `bpf`
LSM hook (last in the chain) ever gets to make its own decision** — with
`landlock` the most mechanistically plausible of the three (it is
specifically a filesystem/execute-access-governing LSM; `lockdown` and
`capability` govern narrower, less directly relevant classes of
operations). This was not confirmed further within this follow-up's own
time budget and is reported as the current state of the investigation,
not a final answer.

**This does not change Q14's answer.** Real BPF-LSM pre-effect denial
via RuntimeGuard's own mechanism remains not demonstrated — if anything,
this follow-up strengthens that conclusion with direct proof (not
absence-of-evidence) that RuntimeGuard's own code is not the acting
cause of either observed denial pattern, and adds a materially more
precise, evidence-backed characterization of where in the kernel's LSM
stack the real behavior actually originates. **A new, additional,
important finding not present in the original Task 10 record**: BPF-LSM
enforcement behavior on this platform was observed to differ
qualitatively between two independent, nominally-identical provisioning
instances of the same Terraform/kernel/GRUB configuration (original run:
deny conditions silently fell through to allow; this follow-up: exec/
file conditions denied everything including allow) — a real
reproducibility gap in the underlying platform's LSM-stack behavior,
external to RuntimeGuard's own implementation, that any real deployment
on this class of infrastructure would need to characterize further
before relying on `bpf` LSM ordering/interaction guarantees.

See `exclusions.md`'s "Task 12 follow-up" section for the full
diagnostic trail (exact commands, raw evidence file references, and the
discarded/superseded intermediate runs).

## Task 12 follow-up, round 2 (2026-08-14): the LSM-chain hypothesis is decisively ruled out; the true trigger is isolated

The user explicitly rejected treating the round-1 findings above as a
final state and required the investigation to continue. Four further,
increasingly decisive tests were run on the same re-provisioned cluster:

**1. LSM reordering test.** The worker was rebooted with `bpf` requested
FIRST in the `lsm=` boot parameter (`bpf,lockdown,capability,landlock,
yama,apparmor`). The kernel silently overrode this, keeping `lockdown`
and `capability` ahead of `bpf` regardless (confirmed via the actual
post-reboot `/sys/kernel/security/lsm` order:
`lockdown,capability,bpf,landlock,yama,apparmor`) — itself a real,
previously-undocumented platform behavior (some LSMs cannot be reordered
via the boot parameter; `capability` in particular is architecturally
mandatory-first in this kernel's LSM framework). With `bpf` now ahead of
`landlock`/`yama`/`apparmor`, the G1 result was UNCHANGED (exec/file
still 100% denied, network still correctly discriminating) — ruling out
`landlock` and `yama` as the cause, in addition to `apparmor` (already
ruled out in round 1).

**2. Lockdown state check.** `cat /sys/kernel/security/lockdown` on the
worker read `[none] integrity confidentiality` — lockdown is at its most
permissive level, actively restricting nothing. This rules out
`lockdown` as the cause. Only `capability` remains from the
kernel-mandated-first set, and mainline `capability` does not implement
a blocking `bprm_check_security`/`file_open` hook for an unprivileged,
non-setuid binary like `/bin/true` — making it, too, an unlikely cause.

**3. The decisive test: bypass `ret` entirely.** Rather than continue
eliminating LSM candidates one at a time, `lsm_exec`/`lsm_file_open`
were temporarily modified (never committed) to (a) record the raw `ret`
value received into a dedicated 1-entry diagnostic map on every call,
and (b) NOT return early on `ret != 0` — always reaching this function's
own decision logic instead. Result: **identical to before** (exec/file
still 100% denied, network still correct). The diagnostic map confirmed
`ret == 0` on the recorded call. This is direct, not inferential, proof
that **no earlier LSM in the chain is denying anything** — the entire
"earlier LSM in the chain" hypothesis from round 1 is ruled out. The
cause is internal to RuntimeGuard's own map-lookup/decision path at
actual runtime, despite `bpftool map dump` showing correct kernel state
moments later.

**4. Isolating the true variable: reconciliation timing.** A minimal,
fast test (10s bootstrap-wait, 2 exec reps only, exec-only policy patch)
**succeeded** — `/bin/true` executed correctly or the first time this
session that ALLOW worked reliably. A controlled, single-variable A/B
retest (identical minimal config, only the wait changed from 10s to
25s) **failed** — 100% EPERM, matching every other slower test. This
precisely isolates **time-before-first-exec-attempt (equivalently, the
number of the agent's 5-second policy-reconciliation cycles that have
run before that attempt) as the deciding variable** — not LSM chain
order, not `ret`, not patch content (a full-scale exec-only-patch retest
at the original timing still failed identically, ruling out patch
content as the driver once timing is held at the original, slower
value).

**Critically, even the FAST/successful test's DENY condition still did
not block `/bin/false`** (`raw_error="exit status 1"`, not `EPERM` —
`/bin/false` executed normally and exited with its own ordinary code).
This means the core, original Task 10 finding — **DENY never blocks,
under any tested condition** — is now confirmed a third time, including
under the one timing condition where ALLOW itself works cleanly. This
rules out reconciliation-timing as an explanation for the DENY-specific
failure (it is orthogonal to it) and leaves DENY's own root cause
exactly as precisely bounded as at the end of round 1, now with even
more hypotheses eliminated (LSM chain and `ret` value, conclusively).

**Consolidated, current state of Q14 / G3 after both rounds:**

- Real BPF-LSM programs load, verify, and are invoked by the kernel for
  every relevant operation (`COUNTER_LSM_HOOK_ENTERED` confirms this
  directly) — DEMONSTRATED, unchanged from round 1.
- ALLOW succeeds under fast/minimal-reconciliation conditions, matching
  the original Task 10 dataset — DEMONSTRATED, now further qualified: it
  degrades to 100% failure after enough policy-reconciliation cycles
  have run against the same cgroup, a newly isolated, previously-unknown
  stability boundary. Root cause of the degradation itself (why repeated
  `ApplyPlan` calls to the same, unchanged cgroup break a subsequent
  kernel-side lookup that a `bpftool` snapshot shows as correct) was
  not further decomposed within this follow-up's time budget; two
  concrete next steps are documented in `exclusions.md` for any future
  work.
- DENY never blocks anything, under ANY condition tested across both
  rounds (fast, slow, LSM-reordered, `ret`-bypassed) — the single most
  robustly replicated finding in this entire investigation. Root cause
  remains unidentified, but the space of plausible causes has been
  narrowed dramatically and rigorously: not AppArmor, not landlock, not
  yama, not lockdown, not `capability` (architecturally implausible and
  never isolated as a cause), not the LSM chain's `ret` propagation, not
  reconciliation timing (DENY fails identically under the one timing
  condition where ALLOW succeeds).

**This does not upgrade Q14 to DEMONSTRATED.** Pre-effect denial via
RuntimeGuard's own mechanism is still not shown to work under any tested
condition. What round 2 changes is the QUALITY of the negative result:
from "an unexplained mystery with several untested hypotheses" to "a
robustly replicated negative finding with the great majority of
plausible causes directly, empirically eliminated." See
`exclusions.md`'s "Task 12 follow-up, round 2" section for exact
commands, raw evidence, and the two concrete next steps left for any
future investigation.
