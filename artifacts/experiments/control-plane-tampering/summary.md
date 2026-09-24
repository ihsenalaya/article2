# Trust-Boundary Hardening — Summary (Task 11)

Addresses experiment protocol Q15 (can a malicious/untrusted control plane
tamper with D -> P without worker detection?) and Task 11's own
before/after requirement.

## The problem, before this task (documented per the protocol's
## explicit "before changing architecture, document the problem" instruction)

Direct code inspection of `ebpf-agent/cmd/agent/main.go` (re-confirmed at
the start of this task, on top of Task 00's original audit finding)
showed the agent never imported, watched, or read `AIPlacementDecision`
(D) at all. It only ever watched `RuntimeSecurityPolicy` (P) — the
operator's OWN derived output — and copied `p.Spec.Derivation.
DecisionHash`/`PolicyHash` (fields the operator itself computed) directly
into signed evidence, with no independent verification. Confirmed
empirically, not just by reading code: a plain `kubectl patch
runtimesecuritypolicy ... allowedPaths:[/bin/sh]` against the pre-Task-11
agent was applied without any rejection.

This is inconsistent with this project's own stated threat model (Task
00): if the Kubernetes control plane is not fully trusted, a worker that
applies whatever policy it receives — with no check against the signed
decision that policy claims to derive from — gives a compromised or
buggy controller (or anyone with `RuntimeSecurityPolicy` write access,
which is a materially different and broader privilege than "can forge a
valid Ed25519-signed placement decision") silent control over enforcement
rules.

## What was implemented

`ebpf-agent/internal/trustverify`, wired into the agent's existing
reconcile loop (`cmd/agent/main.go`), for every `RuntimeSecurityPolicy`
the agent considers applying:

1. **`VerifySignature(D) == true`** — fetches the referenced
   `AIPlacementDecision` (unstructured, since that type is internal/ to
   the operator's separate Go module), decodes its placement token, and
   verifies it via `operator/pkg/token.VerifyForPod` — the SAME
   verification function the operator's own controller calls, reused
   directly rather than reimplemented (eliminating any risk of the two
   verifiers silently drifting apart).
2. **`hash(P_received) == hash(derive(D))`** — the agent independently
   reconstructs the policy the operator's controller would derive from D
   (mirroring `policy_derivation.go`'s current, deliberately minimal
   deny-all-baseline logic — not importable directly, so mirrored field-
   for-field with a comment explaining why) and compares its hash against
   the hash of the policy's ACTUAL received content. This is the check
   that actually catches tampering: comparing against a hash-shaped
   *field* the same attacker could also have rewritten would not be a
   real check.
3. **Freshness, version, anti-replay, Pod UID, node identity** — token
   expiry and pod-UID/node-identity binding via `VerifyForPod`'s existing
   parameters; a new agent-local `ReplayLedger` (in-memory) rejects
   version/epoch rollback and same-version-different-nonce replay. Honest
   limitation, stated in code and here: this ledger does not survive an
   agent restart (unlike the operator's own persistent, ConfigMap-backed
   ledger, which this separate module cannot import).

**On failure, the agent applies a safe deny-all substitute plan** —
`DefaultAction=deny`, empty allow-lists, for every rule category —
instead of the received (untrusted) policy. "The worker rejects it" means
deny, confirmed to actually reach the kernel (see below), not merely
logged.

## Experimental results

| condition | n | expected | matched expected |
|---|---|---|---|
| valid D + correct P | 5 | ACCEPTED | 5/5 |
| valid D + tampered P | 5 | REJECTED | 5/5 |

**Valid D + correct P → accepted (5/5).** Normal decision-minting flow,
steady-state agent log shows `applied policy` with no validation error.

**Valid D + tampered P → rejected (5/5).** Each rep: reached a confirmed
`ACCEPTED` baseline first (proving the policy really was trusted before
tampering, not merely never checked), then `kubectl patch`ed the live
policy's `Exec.AllowedPaths` directly (D itself untouched). Every rep's
next reconcile cycle logged `"Task 11: worker-side D->P validation
FAILED ... hash(P_received) != hash(derive(D))"` and applied the deny-all
fallback instead.

**This is not just a log message.** For the first tampered-P run, direct
`bpftool map dump` of the live `exec_rules` eBPF map (host-namespace
access, `kubectl debug node`) after tampering showed it **empty** — the
tampered `/bin/sh` entry never reached the kernel (`raw/exec-rules-map-
after-tamper.json`). The rejection genuinely changed what got enforced,
not only what got logged.

## Answer to Q15

**No — not undetected, within the scope of this experiment.** A control
plane that tampers with a policy's rule content after the operator
derived it from a genuine, still-valid signed decision is detected by
the worker in 5/5 tested reps, and the worker substitutes a safe
deny-all plan rather than applying the tampered content. This closes the
specific gap Task 00 identified. It does **not** claim a stronger,
unqualified property: the `ReplayLedger`'s in-memory-only nature means a
control plane that can also trigger or wait for an agent restart is
outside what this specific mechanism defends against (see
`exclusions.md`); a control plane that fully compromises the trust-anchor
ConfigMap itself (rather than only `RuntimeSecurityPolicy` objects) could
still forge signatures the agent would accept, since the agent trusts
that ConfigMap's content by design (the same public-key-distribution
trust root the operator itself relies on — defending against a
compromised trust anchor is a key-management problem, not something this
task's mechanism is positioned to solve).

## Limitations

- `n=5` per condition — a deliberately small but real, deliberately-
  designed sample given this task's optional status and the master
  prompt's own framing ("then experimentally test," not a stated `n`
  target like G1/G2's `n>=30`); every rep is independently created and
  torn down, not repeated assertions against one setup.
- The derivation this task mirrors (`policy_derivation.go`) is currently
  a deny-all baseline mostly independent of D's own content beyond
  identity fields — an existing, pre-Task-11 simplification this task
  faithfully mirrors rather than changes. A future richer derivation
  (policy content that actually varies with D's payload) would need this
  mirror updated in lockstep, a maintenance burden stated explicitly in
  `trustverify.go`'s doc comment.

## Task 12 follow-up (2026-08-14): both remaining limitations closed and verified live

The user explicitly required both limitations above resolved, not left
standing. Both are now closed with real code and live, on-cluster
verification (not just unit tests):

**Anti-replay ledger now persists across agent restarts.**
`trustverify.NewReplayLedgerPersistent(path)` loads existing state from a
node-local JSON file on startup and writes back (temp-file-then-rename)
after every `CheckAndRecord` call; wired into `cmd/agent/main.go` via a
new `--replay-ledger-path` flag, backed by a `hostPath` volume mounted at
`/var/lib/runtime-guard-agent` in `agent-daemonset.yaml`. **Verified
live**: a real decision was applied (`ledger-persist-test`, epoch=1/
version=1), confirmed written to
`/var/lib/runtime-guard-agent/replay-ledger.json` on the worker node,
then the agent pod was deleted and rescheduled on the SAME node. The
fresh agent process, on reload, correctly REJECTED a replayed decision
carrying the same (epoch, version) with a different nonce —
`"anti-replay: decision ... seen before with a different nonce
(replay)"` — using state loaded from disk, not a freshly-empty ledger
that would have wrongly accepted it as a first sighting. This closes the
"malicious control plane colluding with an agent restart" scenario the
original limitation named explicitly. Scope boundary stated plainly:
this is node-local persistence, not cluster-wide — a pod rescheduled to
a DIFFERENT node still starts with an empty ledger on that node.

**Trust-anchor-ConfigMap compromise now has a real, bounded mitigation
(Trust-On-First-Use pinning), not silence.** The prior limitation
("defending against a compromised trust anchor is a key-management
problem, not something this task's mechanism is positioned to solve")
is not something a single task can fully solve without relocating the
root of trust (HSM, multi-party signing, remote attestation — a
different architecture, genuinely out of scope here) — but leaving it
completely undefended was rejected as unacceptable. `LoadTrustAnchorTOFU`
pins the scheduler's public key to a node-local file on first use and
refuses (fails closed, triggering deny-all via the existing "nil key"
path) if a LATER read of the ConfigMap shows a DIFFERENT key — catching
exactly the "control plane silently swaps in an attacker key" scenario,
whether from compromise or an unannounced rotation. **Verified live**:
the pin file (`/var/lib/runtime-guard-agent/trust-anchor.pin`) was
confirmed present and correct (matching the real
`PUBLIC_KEY_HEX`) and to have SURVIVED every one of the many agent
restarts/redeployments performed during this follow-up session without
being reset — real evidence of persistence across restarts on the same
node, not just a unit-test claim. Explicitly documented, not silently
assumed: this does NOT defend against compromise that occurs BEFORE the
node's first pin (day-zero), and does NOT defend against an attacker who
also controls the node's local filesystem (raising the bar to
node-level compromise, not eliminating the risk) — a planned, legitimate
key rotation is handled via an explicit, auditable, privileged action
(delete the pin file to re-arm), not a silent bypass. See
`ebpf-agent/internal/trustverify/trustverify.go`'s
`LoadTrustAnchorTOFU` doc comment for the complete, precise scope
statement.

Both mechanisms have dedicated unit tests
(`trustverify_test.go`: `TestReplayLedgerPersistent_*`,
`TestLoadTrustAnchorTOFU_*`, 6 new tests, all passing) in addition to
the live verification above.
