# Experiment D — Kubernetes Identity Regression — Summary

Task 07. Addresses experiment protocol Q10 and section 9's regression/anti-pattern
validation requirement.

**This is explicitly a regression test, not a claim of novel contribution.**
Pod UID as an identity anchor is not new; this experiment validates that an
existing fix (commit `487a57e`, 2026-08-10, the "H100-E04/E09" finding) still
holds under this campaign's rebuilt CPU environment and current code.

## Scenario

1. Pod A (name X, namespace Y) is created; a real, Ed25519-signed
   `AIPlacementDecision` is minted bound to Pod A's actual UID (u_A); the
   resulting `RuntimeSecurityPolicy` reaches `EnforcementReady` with
   `Status.Decision == "active"`.
2. Pod A is deleted. **The decision/policy object is deliberately left in
   place, unchanged** — this tests whether the *original* policy becomes
   active for the recreated pod, matching the protocol's exact framing
   ("Policy(A) MUST NOT become active for B"), not a fresh policy for B.
3. Pod B is recreated at the identical Name+Namespace. Kubernetes assigns it
   a new UID (u_B).
4. After waiting 4 poll cycles (20s), external cluster/log state (never
   workload self-report) is checked for whether the stale policy ever bound
   to Pod B.

## Result

n=10 independent recreations (raw/d1-pod-recreation.jsonl,
processed/d1-pod-recreation-summary.csv):

| check | pass count |
|---|---:|
| `u_A != u_B` (Kubernetes generated a genuinely new identity) | 10/10 |
| `RuntimeSecurityPolicy.Status.appliedCgroupIDs` unchanged after B's creation (no new bind occurred) | 10/10 |
| Agent's "pod UID mismatch... refusing to bind" warning observed, naming this policy and B's real UID, after B's creation | 10/10 |
| `RuntimePlacementEvidence.Status.PodUID` never became B's UID | 10/10 |
| **Overall: policy did NOT become active for B** | **10/10** |

**Q10 answer: yes — policy binding correctly does not survive Kubernetes
Pod recreation with the same Name+Namespace and a new UID.** The result is
unanimous and unambiguous across all 10 trials: `u_A != u_B` held in every
case (confirming the underlying threat model is real — Kubernetes does
generate a fresh UID on every recreation, so an attacker deleting a
legitimate pod and recreating one at the same name genuinely gets a
different identity), and in every case the agent's UID-mismatch check
(`ebpf-agent/cmd/agent/main.go` `reconcileOnce`) refused to bind, with the
refusal independently confirmed via the agent's own log output rather than
inferred from absence of a failure.

## What "refusing to bind" concretely means for Pod B

Pod B is left with **no applied policy at all** during this window — not a
fail-safe deny-by-default cgroup config, but a cgroup with no
`cgroup_config` entry whatsoever. Per Task 00's original audit of
`agent.bpf.c`'s hooks (`if (!cfg) return 0;`), an unconfigured cgroup is
invisible to the eBPF hooks: Pod B's operations are neither enforced nor
observed until a *fresh* decision (bound to `u_B`) is minted and applied.
This is the same fail-open startup window Task 00/04 already characterized
for the normal admission path — Task 07 confirms it also applies, correctly
and by design, to a pod recreated at a previously-authorized name, rather
than that prior authorization being inadvertently inherited (which would be
the worse failure mode: silent over-authorization instead of a
characterized, bounded window of no coverage).

## Forbidden-claim-word check

Per experiment protocol rule 16, this summary does not claim the identity binding
mechanism is itself a novel contribution (the experiment protocol explicitly
prohibits this framing) and does not claim "complete observation" for the
gap window described above — that gap is Task 00/04's territory, referenced
here, not re-measured.

## Limitations

- n=10, matching the protocol's stated target exactly (not exceeded).
- Only the "delete A, recreate B, decision left untouched" scenario was
  tested. A related but distinct scenario — Pod A deleted AND its decision
  revoked, then a *fresh* decision minted for Pod B — was already
  effectively exercised by Task 06's revocation experiments (which mint
  fresh per-run decisions) and is not repeated here.
- No bugs were found in this experiment; see `exclusions.md` for the (empty,
  by design) discarded-runs account — the campaign's discipline of
  documenting bugs applies equally to documenting their absence, not just
  their presence.
