# Phase 5 — Functional validation on kind: summary

Raw data backing every claim below lives alongside this file
(`evidence-*.json`, `policy-*.json`, `agent-logs-*.json`), captured via
`kubectl get -o json` / `kubectl logs`, unedited. See `EXPERIMENTS_LOG.md`
for the full narrative, including every bug found and fixed while producing
these results.

## Setup

- Cluster: dedicated `kind-article2` (2 nodes), never the pre-existing
  `greenops`/`kubeupgrade-test` clusters on this machine.
- Real model weights: `Qwen/Qwen2.5-0.5B-Instruct` (Apache 2.0), 988097824
  bytes, sha256 `fdf756fa7fcbe7404d5c60e26bff1a0c8b8aa1f72ced49e7dd0210fe288fb7fe`,
  downloaded from HuggingFace and copied onto both kind nodes.
- 3 workloads (`experiments/workloads-kind.yaml`): `llm-inference` (real
  weight-file read + legitimate egress), `rag-pipeline` (real Qdrant +
  document reads + Qdrant query), `gpu-workload` (weight-file read +
  simulated `/dev/nvidia0` open — no real GPU on this dev machine; explicitly
  "simulable sur kind" per the experiment plan, to be revalidated on real
  H100 hardware in Phase 9).
- Real signed `AIPlacementDecision` objects minted via
  `operator/cmd/mint-test-decision` against the trust-anchor key, applied for
  all 3 workloads — not fabricated CRD state.
- Agent ran in **audit-only mode** throughout (BPF-LSM inactive on this
  kernel — see Phase 0), consistent with the plan's requirement to validate
  audit-only behavior before any enforce-mode claim.

## Attack scenarios and results

| # | Scenario | Workload | Result |
|---|---|---|---|
| A1 | Exec of a disallowed binary (`/bin/ls`) | llm-inference | Detected: `execDenied` +1 immediately after the attempt |
| A2 | Read of an unauthorized file (`/etc/shadow`) | llm-inference | Detected: `fileOpenDenied` increased |
| A3 | Outbound connect to a forbidden destination | llm-inference | Detected: `connectDenied` +1 immediately after the attempt |
| A4 | Unauthorized device access (`/dev/nvidia0`) | gpu-workload | Detected continuously: `deviceAccessDenied` increments every ~15s (workload's own periodic access, never allowlisted) |
| A5 | Persistence of access after revocation | gpu-workload | **Closed**: deleting the `AIPlacementDecision` (→ owner-reference garbage-collects the `RuntimeSecurityPolicy`) causes the agent to flip the pod's cgroup(s) to deny-by-default within one poll cycle (~5s). Verified over a 90s window: `execAllowed`/`fileOpenAllowed`/`connectAllowed` all froze at the instant `status.revokedAt` was set, while `execDenied`/`fileOpenDenied`/`connectDenied` kept climbing — i.e. previously-legitimate activity is denied, not silently ignored, after revocation. |

All decisions above are `DECISION_AUDIT_WOULD_DENY` (observed, not blocked —
audit mode cannot block, only enforce mode can; see DESIGN.md). Real
enforcement (actually blocking) requires BPF-LSM active, which this dev
kernel does not have — that claim is deferred to Phase 9's AKS pre-flight,
not asserted here.

## Real bugs found during Phase 5 (in addition to the 10 from Phases 0–4)

1. **cgroup nesting** (#11, most significant): containerd creates a per-container
   leaf cgroup nested under the pod-level slice; `bpf_get_current_cgroup_id()`
   resolves to that leaf, never the pod-level directory. Fixed in
   `internal/cgroupmap` (multi-cgroup-per-pod resolution).
2. **Missing signature timestamps** (#12): `EvidenceSignature.IssuedAt/ExpiresAt`
   were never copied from the signed payload into the CRD status, causing
   every evidence update to fail CRD validation. Fixed.
3. **Missing `open(2)` coverage** (#13): only `openat(2)` was hooked; BusyBox's
   `cat` uses the legacy `open(2)` syscall on this architecture, making its
   file reads completely invisible (not even counted as denied). Fixed by
   adding a `sys_enter_open` tracepoint mirroring `sys_enter_openat`.
4. **Revocation evidence blackout**: the first revocation implementation
   stopped updating a pod's evidence entirely once revoked, making it
   impossible to observe whether post-revocation activity was actually
   denied. Fixed by keeping revoked pods tracked (with `revokedAt` set) until
   their underlying Pod object is actually gone.

## Documented limitations surfaced by real testing (not merely anticipated)

- **Exact-match file policy over-flags routine access.** With
  `FileAccessPolicy.DefaultAction=deny` and only one exact path allowlisted,
  every other file a process opens as part of ordinary operation (DNS
  config, `/proc` reads, etc.) is flagged as a violation too, not just the
  deliberate attack. This is the documented exact-match-only limitation
  (see `bpf/common.h`) manifesting concretely: a real deployment would need
  either a much larger curated allowlist or real prefix/glob matching
  (a documented future enhancement, not implemented here).
- **`/dev/null`-style redirects count as device access.** The device
  classification is a `/dev/` path-prefix check; ordinary `> /dev/null`
  redirects are technically device opens too and get denied by default
  unless explicitly allowlisted. A production policy would allowlist a
  small set of benign pseudo-devices by default.
