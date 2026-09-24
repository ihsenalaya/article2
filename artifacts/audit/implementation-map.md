# TASK 00 — Repository and Implementation Audit

Git commit audited: `487a57e55c139c6643314fd173836f68df62b24e` (branch `main`, 2026-08-13).
Method: direct source inspection only (no execution, no inference). Every claim below is
anchored to a file:line citation. Where a claim could not be verified statically and needs
runtime confirmation, it is marked `NEEDS EMPIRICAL VERIFICATION` — those become Task 04/05/06
experiments.

No code was changed in this task, per the protocol's Task 00 scope.

## 0. Component inventory

Two independent Go modules:

- `operator/` — in-cluster controller-runtime manager (`operator/cmd/main.go`). Runs as a
  Kubernetes Deployment. Watches article 1's `AIPlacementDecision` (upstream CRD, not owned by
  this repo — `operator/internal/upstream/aiplacementdecision.go`) and this repo's own
  `RuntimeSecurityPolicy` / `RuntimePlacementEvidence` CRDs (`operator/api/v1alpha1/`).
- `ebpf-agent/` — per-node privileged DaemonSet (`ebpf-agent/cmd/agent/main.go`). Loads the BPF
  object (`ebpf-agent/bpf/agent.bpf.c`), lists `RuntimeSecurityPolicy` objects via the K8s API,
  writes BPF maps, reads the ring buffer, and emits `RuntimePlacementEvidence`.

Plus two CLI helpers: `operator/cmd/runtime-guard-launcher` (workload-side cooperative gate) and
`operator/cmd/verify-evidence` (standalone offline verifier — **not** wired into any live
reconciler, see §9).

## 1. Pipeline stage → component → file:line

| Pipeline stage | Component | Runs where | File:line |
|---|---|---|---|
| Signature verification of D | `AIPlacementDecisionReconciler.evaluate` → `placementtoken.Verify` | **Operator (control plane)** | `operator/internal/controller/aiplacementdecision_controller.go:226`, `operator/pkg/token/token.go:67-104` |
| Anti-replay | `reserveDecision` (nonce check) | **Operator (control plane)**, state in a ConfigMap (`runtime-guard-decision-ledger`) | `operator/internal/controller/decision_ledger.go:73-83` |
| Rollback protection | `reserveDecision` (epoch/version regression check) | **Operator (control plane)** | `operator/internal/controller/decision_ledger.go:67-72` |
| Policy derivation `derive(D)→P` | `derivePolicySpec` | **Operator (control plane)** | `operator/internal/controller/policy_derivation.go:33-102` |
| Pod UID validation | Two places, see §3 | Operator (embeds `Binding.PodUID` into P) **and** ebpf-agent (compares live pod UID to `Binding.PodUID`) | `aiplacementdecision_controller.go:245`; `ebpf-agent/cmd/agent/main.go:238-249` |
| Cgroup binding | `podTracker.resolver.Track` | **ebpf-agent (node/worker)**, from real host cgroupfs | `ebpf-agent/cmd/agent/main.go:251`, `ebpf-agent/internal/cgroupmap/cgroupmap.go` |
| PolicyReady / EnforcementReady | `markPolicyEnforcementReady` | **ebpf-agent (node/worker)**, only after `ApplyPlan` succeeds | `ebpf-agent/cmd/agent/main.go:284, 380-428` |
| Release gate | `runtime-guard-launcher` main loop | **Workload-side CLI, cooperative** | `operator/cmd/runtime-guard-launcher/main.go:83-119` |
| eBPF loading | `loader.Load` (mode selected by `lsmdetect.DetermineMode`) | **ebpf-agent (node/worker)** | `ebpf-agent/internal/loader/loader.go:87-134`, `ebpf-agent/internal/lsmdetect/lsmdetect.go:51-59` |
| Event collection | ring buffer reader → `accumulator.handle` | **ebpf-agent (node/worker)** | `ebpf-agent/internal/loader/loader.go:345-366`, `ebpf-agent/cmd/agent/main.go:601-634` |
| Evidence production | `emitEvidence` | **ebpf-agent (node/worker)** | `ebpf-agent/cmd/agent/main.go:470-581` |
| Evidence signing | `evidence.Sign` (Ed25519, agent's own node-local key) | **ebpf-agent (node/worker)** | `operator/pkg/evidence/evidence.go:59-81`, invoked at `ebpf-agent/cmd/agent/main.go:518` |
| Revocation detection | `reconcileOnce` tail loop (policy absent from list ⇒ revoke) | **ebpf-agent (node/worker)**, driven by a **5-second fixed poll**, no watch | `ebpf-agent/cmd/agent/main.go:330-377`; poll interval default at `main.go:61` (`5*time.Second`) |
| Evidence verification | `verifyEvidence` | **Standalone offline CLI only** — see §9 | `operator/cmd/verify-evidence/main.go:95-147` |

## 2. CRITICAL TRUST-BOUNDARY QUESTION

> Can a compromised Kubernetes controller/operator transform valid D into malicious P without the
> worker detecting it?

**Yes.** This is a code-level finding, not inference:

1. Ed25519 signature verification of D (`placementtoken.Verify`) happens **exactly once**, inside
   `AIPlacementDecisionReconciler.evaluate` in the Operator
   (`aiplacementdecision_controller.go:226`). No other component in this repository imports
   `operator/pkg/token` to re-verify a decision. In particular, `ebpf-agent` never imports
   `operator/pkg/token` at all (confirmed by import list of `ebpf-agent/cmd/agent/main.go:17-47`)
   — it has no code path capable of checking D's signature.

2. `derive(D)→P` (`derivePolicySpec`, `policy_derivation.go:33-102`) also runs **only** in the
   Operator. It computes `DecisionHash`, `PolicyHash`, `TokenHash` and stamps them into
   `RuntimeSecurityPolicy.Spec.Derivation` — but this is the Operator **self-reporting** hashes of
   its own output. Nothing outside the Operator recomputes `derive(D)` independently and compares.

3. `ebpf-agent`'s `reconcileOnce` obtains P purely via a plain, unauthenticated-at-the-application-layer
   K8s API list (`c.List(ctx, &policies)`, `main.go:221`) and applies it directly:
   `policy.BuildPlan(cgroupID, p, enforcementMode)` → `bpfAgent.ApplyPlan(plan)`
   (`main.go:266-279`). There is no call anywhere in `ebpf-agent` that checks
   `hash(P_received) == hash(derive(D))`, nor one that re-verifies `Spec.Derivation.DecisionHash`
   against a recomputed value. The `Derivation` struct fields are read only to be **copied
   verbatim** into evidence (`main.go:304-305`, `489-491`) — never validated.

4. The **one** independent worker-side check is Pod UID binding
   (`main.go:238-249`): the agent compares the *live* Pod object's real UID (read from the API
   server, not from D) against `p.Spec.Binding.PodUID` — but `Binding.PodUID` is itself a field of
   P, populated by the Operator from its own verified copy of D
   (`aiplacementdecision_controller.go:245`). This blocks a **stale-binding** replay (an old P
   reused after pod recreation, Task 07's regression scenario) but does **not** block a
   compromised Operator from fabricating a *different, more permissive* P (e.g.
   `EnforcementMode: audit` when D said `enforce`, or `DefaultAction: allow` when D said `deny`)
   **for the correct, currently-running pod's real UID**. Nothing in `ebpf-agent` would detect
   that tampering: the UID check would pass, `ApplyPlan` would succeed, and
   `EnforcementReadyAt` would be set — all with a policy that no longer matches what D actually
   authorized.

**Conclusion**: the worker does **not** independently verify D and/or P. Verification is
performed exclusively by the Operator, which per the paper's own threat model is part of the
untrusted control plane. A compromised Operator can transform valid D into malicious P without
worker-side detection, limited only by the Pod-UID binding check (§3 above). This is exactly the
condition Task 11 (optional trust-boundary hardening) is scoped to address, and it is
**currently unmitigated** in the audited commit.

## 3. Release gate: externally enforced barrier, or cooperative protocol?

Two structurally different mechanisms exist in this codebase, and the protocol's "release
gate" concept maps to *both*, imperfectly:

**(a) `runtime-guard-launcher` (workload-side wait/release)** — `operator/cmd/runtime-guard-launcher/main.go:83-119`.
Polls `RuntimeSecurityPolicy.Status` every `poll-interval` (default 500ms) and only after
`isCurrentEnforcementReady` (`main.go:122-131`) writes a ready-file and lets the calling container
proceed. This is **pure cooperative orchestration**: it is a CLI binary a workload's entrypoint
chooses to invoke and wait on. Nothing prevents a container image from skipping it entirely and
executing its real workload immediately. It has zero kernel-level enforcement capability by
construction — it only reads the K8s API and writes a file.

**(b) The eBPF/LSM hooks themselves (`ebpf-agent/bpf/agent.bpf.c`)** — this *is* a kernel-level
mechanism, but conditionally:
- It can only actually deny (`return -1` / EPERM) when `cfg->enforcement_mode == HOOK_MODE_ENFORCE`
  *and* the node's active LSM chain contains `"bpf"` (`lsmdetect.DetermineMode`,
  `lsmdetect.go:51-59`) — i.e. `ModeEnforce`. In `ModeAudit` (tracepoints only,
  `loader.go:142-170`), the hooks structurally cannot influence syscall outcomes at all
  (tracepoint return values are ignored by the kernel) — see the doc comment at
  `agent.bpf.c:9-15`.
- **Fail-open on missing policy.** Every hook — `trace_execve` (`agent.bpf.c:249-250`),
  `handle_file_open` (`agent.bpf.c:279-280`), `trace_connect` (`agent.bpf.c:317-318`),
  `lsm_exec` (`agent.bpf.c:346-347`), `lsm_file_open` (`agent.bpf.c:371-372`), `lsm_connect`
  (`agent.bpf.c:399-400`) — does `if (!cfg) return 0;` when `cgroup_configs` has no entry for the
  calling cgroup. `return 0` in an LSM hook is **ALLOW**. This is explicitly documented as
  intentional at `agent.bpf.c:149-165` for the revocation case (a missing entry must not be
  confused with "revoked"), but it has an equally real converse consequence: a **brand-new pod's
  cgroup has no `cgroup_configs` entry until the ebpf-agent's poll loop (`pollLoop`,
  `main.go:203-216`, default interval 5s, `main.go:61`) reaches it and calls `ApplyPlan`**. Any
  process that execs/opens/connects inside that cgroup *before* that first `ApplyPlan` call faces
  **no enforcement and no denial decision at all** — the hook returns ALLOW with no policy
  context, not even an audit "would-deny" event (the audit tracepoints do emit an event, but only
  once `cfg` exists; before that, `get_cgroup_config` returns NULL and `emit_event` is never
  called — the operation is completely unobserved, not merely unenforced).

**Conclusion (code-level basis, requires Task 04-A4 empirical confirmation):** the release
mechanism, as experienced by a **non-cooperative** workload, is not a non-bypassable barrier. The
launcher is unconditionally cooperative. The eBPF/LSM layer is a real kernel control only after
(i) the node has BPF-LSM active, (ii) the policy is `enforce` mode, and (iii) the poll loop has
already applied that pod's cgroup — and it fails open, silently and unobserved, for the interval
before (iii). `NEEDS EMPIRICAL VERIFICATION`: measure the actual startup-window duration and
whether A4's non-cooperative workload's critical operation lands inside it (Task 04).

## 4. Evidence verification is not currently a live, continuous process

`RuntimePlacementEvidenceReconciler.Reconcile` (`operator/internal/controller/runtimeplacementevidence_controller.go:48-51`)
is a **no-op**: `return ctrl.Result{}, nil`. The only code that actually calls `evidence.Verify`
(`operator/pkg/evidence/evidence.go:83-106`) plus the cross-field checks (decision-hash,
policy-hash, pod-uid, agent-image-digest, freshness) is `operator/cmd/verify-evidence/main.go`, a
**standalone CLI** that must be manually pointed at exported evidence/policy files
(`verifyFiles`, `main.go:68-82`). There is no in-cluster component that automatically verifies
`RuntimePlacementEvidence` as it is produced. This is directly relevant to Q3/Q5/Q7: currently
**nothing in the running cluster** would flag stale, incomplete, or post-revocation evidence as
such — that judgment only happens if and when a human/CI process runs `verify-evidence` offline.

## 5. Observation completeness gaps found by static inspection (feeds Task 05)

- **No event-loss accounting exists.** `bpf_ringbuf_reserve` can fail (ring buffer full) —
  `emit_event`'s handling is `if (!e) return;` (`agent.bpf.c:213-215`) with **no counter
  increment anywhere**, kernel-side or user-space-side. `NEEDS EMPIRICAL VERIFICATION`
  (Task 05-B1): confirm whether sustained high event rates actually trigger this path and by how
  much events are undercounted with zero indication in evidence.
- **No monitor-liveness / heartbeat fields exist.** `evidence.Payload` (`evidence.go:14-37`) has
  no `monitorEpoch`, `hookSetDigest`, `lastHeartbeat`, or `dropCount` field. `EvidenceSequence`
  exists (a per-pod monotonic counter with hash-chaining via `PreviousDigest`) but nothing
  currently checks for *gaps* in that sequence, or for the evidence loop having stopped entirely
  (an agent process death, or a detached hook, currently produces **silence**, not an explicit
  `INCOMPLETE`/error state — a verifier reading only the last-seen evidence object cannot
  distinguish "workload is quiet" from "monitor is dead", matching Q5 exactly).
- **`Conformance` is binary (`conform`/`violation`)** (`main.go:479-482`) — computed only from
  `*Denied` counters being nonzero. It cannot represent `INCOMPLETE`/degraded-observation states.

## 6. Revocation / authorization-vs-compliance semantics (feeds Task 06)

- Revocation is detected **only** by a policy disappearing from the next `c.List` poll result
  (`main.go:334-338`), on the same fixed `pollInterval` (default 5s) used for policy application
  — this is the current architecture, not merely a historical artifact of a prior experiment. The
  protocol's premise that "mean revocation propagation = 3.49s was dominated by a fixed 5-s
  polling period" is corroborated: the poll interval is a compile-time-default, code-level
  constant today (`main.go:61`), not derived from any event-driven signal. No K8s `watch` is used
  anywhere in `ebpf-agent` (confirmed: `pollLoop` uses `time.NewTicker`, `main.go:203-216`; no
  `client.Watch` call in the package).
- `RevokedAt` (`RuntimePlacementEvidence.Status.RevokedAt`) is explicitly **not part of the signed
  evidence payload** — see the doc comment at `main.go:567-573` and the absence of a `RevokedAt`
  field in `evidence.Payload` (`evidence.go:14-37`). It is informational status only; the
  authenticated signal of revocation-after-the-fact is instead the signed `Behavior` counters
  (`*Denied`) continuing to increase.
- There is **no `authorizationEpoch` / `authorizationState` / `authorizationValidUntil` field**
  anywhere in `evidence.Payload` or `RuntimeSecurityPolicySpec`
  (`operator/api/v1alpha1/runtimesecuritypolicy_types.go`). `Conformance` = `conform` reports
  *behavioral compliance with the currently-applied cgroup map contents*, which is not the same
  claim as *"this pod's placement is currently authorized"* — i.e. `COMPLIANT != AUTHORIZED` is
  architecturally real today (a revoked-but-not-yet-processed pod could still show `conform` if it
  simply hasn't attempted a denied operation), but the schema does not yet make that distinction
  explicit or verifiable. `RevocationTTLSeconds` exists in the policy spec
  (`runtimesecuritypolicy_types.go:258-264`) as a target/bound field but nothing in the audited
  code currently measures against it or enforces it.
- Revocation is transported exclusively through the (untrusted, per threat model) Kubernetes API
  server / etcd — there is no cryptographically signed revocation record; the agent trusts
  "policy object absent from list" as the sole revocation signal, unauthenticated beyond ordinary
  K8s RBAC/API-server TLS.

## 7. What is genuinely worker-independent today

For balance: not everything is blindly trusted. Three things are real, worker-local facts, not
control-plane-supplied claims:
- **Cgroup ID resolution** (`cgroupmap.Resolver.Track`) reads the live host cgroupfs, not the API.
- **`EnforcementReadyAt`** is set by the agent itself only after its own `ApplyPlan` call
  succeeds — the Operator cannot forge "the worker applied this" by writing to Status (the
  ebpf-agent runs `c.Status().Update` on its own view, `main.go:415`, and the Operator's own
  reconciler for this CRD is a no-op, §9 above — so nothing else writes this field).
- **Evidence signing key** is agent-node-local (`AGENT_SIGNING_KEY_HEX`, `main.go:64,84`), not
  supplied by the Operator, so the Operator cannot forge evidence *as if from the agent* — it can
  only forge the *policy* the agent then faithfully (and unsuspectingly) applies.

## 8. Items explicitly NOT determined by this audit (require Task 04-06 experiments)

1. Actual observed duration of the fail-open startup window (§3) under real Azure CPU node
   conditions — code guarantees the mechanism exists, not its magnitude.
2. Actual event-loss rate under load (§5) — code guarantees the *absence of accounting*, not the
   *absence of loss*.
3. Actual revocation-to-effect latency distribution as a function of poll period (§6).
4. Whether a verifier fed real captured evidence would in practice accept a stale
   "AUTHORIZED + COMPLIANT"-shaped proof issued in `[t_rev, t_invalid)` (§6, Q7) — the schema gap
   is established; the exploit needs to be demonstrated, not assumed.

## Self-review (Task 00)

1. **Required**: inspect code (not infer) to map D→P→verifier pipeline stages to components, and
   answer the trust-boundary and release-gate questions with file:line evidence, without making
   any fixes.
2. **Implemented**: full read of `operator/{cmd,internal,pkg,api}` and `ebpf-agent/{cmd,internal,bpf}`
   relevant source files; produced this document with per-stage file:line citations.
3. **Measured**: nothing (Task 00 is audit-only by the protocol's own rule — "Do not fix
   anything yet during Task 00"). All quantitative claims deferred and explicitly flagged
   `NEEDS EMPIRICAL VERIFICATION`.
4. **Acceptance criteria passed**: all `implementation-map.md` required content items (§2 list in
   the experiment protocol: signature verification, anti-replay, rollback protection, policy derivation,
   Pod UID validation, cgroup binding, PolicyReady, release, eBPF loading, event collection,
   evidence production, evidence signing, revocation detection, evidence verification) are
   addressed with file:line citations; trust-boundary question answered from code; release-gate
   classified (A vs B) with code basis.
5. **Acceptance criteria failed**: none for Task 00's own scope. (Quantitative/empirical claims
   are out of scope for Task 00 by design and are deferred, not failed.)
6. **Requirements from experiment protocol remaining unsatisfied**: everything in Tasks 01-11 — this is
   task 1 of 12+.
7. **Did I infer anything not measured?** No numeric or behavioral claim is asserted as
   established fact without a file:line citation; every dynamic/runtime claim is explicitly
   labeled `NEEDS EMPIRICAL VERIFICATION` and deferred to the corresponding experiment task.
8. **Sample sizes**: N/A — no experiments run in this task.
9. **Hidden confounders**: this audit reflects commit `487a57e5` only; any code change in later
   tasks invalidates specific file:line citations here and must be re-verified, not assumed
   stable.
10. **Is any conclusion stronger than the data?** The trust-boundary conclusion (§2) and the
    fail-open startup-window mechanism (§3) are stated as definite because they are structural
    code facts (an absent function call, an explicit `if (!cfg) return 0`), not measurements —
    this is the correct epistemic status for a static-audit task. Their *practical magnitude/
    exploitability* is explicitly left open pending Tasks 04/05/06/11.
11. **Raw data complete?** N/A (no raw data collected in an audit task).
12. **Reproducible?** Yes — every claim cites an exact file:line in a specific commit SHA; another
    researcher can open the same commit and verify each citation directly.
13. **What must be corrected before starting the next task?** Nothing blocks Task 01. Task 01
    (Azure CPU environment) has no dependency on this audit's findings; Task 03 (timestamp
    semantics) and Task 11 (trust-boundary hardening) are the tasks whose design should directly
    incorporate §2/§3/§6 of this document.
