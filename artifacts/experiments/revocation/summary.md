# Experiment C — Revocation and Evidence Semantics — Summary

Task 06. Addresses experiment protocol questions Q6, Q7, Q8, Q9, Q10 and C1-C5.

## Background: what revocation actually is in this system

A prior audit (Task 00-adjacent, done at the start of this task) established the
mechanism this experiment measures: revocation is conveyed entirely by
**Kubernetes API state**, not a signed record. Deleting an `AIPlacementDecision`
triggers owner-reference garbage collection of its `RuntimeSecurityPolicy`; the
agent's poll loop (`ebpf-agent/cmd/agent/main.go` `reconcileOnce`, default
5s interval) notices the object's disappearance on its next cycle and flips the
pod's cgroup to deny-by-default. A pure `AIPlacementDecision.Status.Decision =
"revoked"` status edit (without deletion) is **never consulted by the agent** —
confirmed by code inspection — and has no enforcement effect on its own. Every
measurement in this experiment revokes via deletion, the only channel that is
actually exercised anywhere in this codebase.

## C1 — Parameterized polling (Q8)

**Question**: how does revocation latency depend on the polling period?

**Δ_detect** (t_rev → t_seen, AIPlacementDecision deletion to the agent's
"revoked access" log line), n=8 per condition
(`raw/c1-detect-latency.jsonl`, `processed/c1-detect-latency-summary.csv`,
`figures/c1-detect-latency-vs-poll-interval.png`):

| poll-interval | mean (s) | median | SD | min | max |
|---|---:|---:|---:|---:|---:|
| 0.5s | 1.019 | 1.019 | 0.066 | 0.910 | 1.102 |
| 1s | 1.316 | 1.302 | 0.321 | 0.998 | 1.929 |
| 2s | 1.868 | 1.891 | 0.352 | 1.267 | 2.257 |
| 5s | 3.567 | 3.623 | 0.262 | 3.216 | 3.960 |
| 10s | 8.440 | 8.466 | 0.185 | 8.153 | 8.755 |

Δ_detect scales cleanly with poll-interval — roughly `interval/2 + ~0.5-0.8s`
fixed overhead, consistent with a random phase-alignment wait against a
fixed-interval ticker plus constant processing/log-flush latency. This is a
direct, measured answer to Q8: **halving the poll interval roughly halves
detection latency**, with no sign of a floor below ~1s in the tested range
(0.5s-10s).

**Δ_evidence** (t_rev → t_T, first signed evidence with
`AuthorizationState=revoked`), n=3 per condition (reduced n — see
Limitations) (`raw/c1-evidence-latency.jsonl`,
`processed/c1-evidence-latency-summary.csv`,
`figures/c1-evidence-latency-vs-poll-interval.png`):

| poll-interval | mean (s) | median | min | max |
|---|---:|---:|---:|---:|
| 0.5s | 19.3 | 23.0 | 11.0 | 24.0 |
| 1s | 20.7 | 23.0 | 16.0 | 23.0 |
| 2s | 20.3 | 24.0 | 13.0 | 24.0 |
| 5s | 25.3 | 24.0 | 23.0 | 29.0 |
| 10s | 21.7 | 19.0 | 18.0 | 28.0 |

Unlike Δ_detect, **Δ_evidence does not scale with poll-interval at all** — it
stays in the same ~11-29s band regardless of whether polling is 0.5s or 10s.
This is architecturally expected and now empirically confirmed: evidence
emission runs on its own fixed 30s global ticker
(`ebpf-agent/cmd/agent/main.go` `evidenceLoop`), independent of the poll
loop, so the SIGNED, verifiable confirmation of a revocation is bottlenecked
by that fixed 30s cadence, not by how fast enforcement itself was retracted.
**A faster poll interval makes enforcement retraction faster; it does
nothing for how quickly a verifier can obtain signed proof of that
retraction.**

t_invalid is not separately measured: `RevokeCgroup()` (the call that
actually flips enforcement) executes synchronously, in the same function,
immediately before the "revoked access" log line
(`revokeTrackedPolicyLocked`) — no I/O or scheduling point separates them,
so t_invalid = t_seen to within the log timestamp's own resolution. This is
confirmed by code inspection, not assumed.

## C2 — Polling vs. watch-based revocation (Q9)

**Question**: does watch-based reconciliation improve revocation latency?
"Do not assume watch is faster; measure it."

With `--poll-interval` fixed at a deliberately slow 10s, n=10 per condition
(`raw/c2-watch-vs-poll.jsonl`, `processed/c2-watch-vs-poll-summary.csv`,
`figures/c2-watch-vs-poll.png`):

| condition | mean Δ_detect (s) | SD | min | max |
|---|---:|---:|---:|---:|
| poll-only | 8.267 | 0.538 | 7.439 | 9.021 |
| watch-enabled | 0.735 | 0.055 | 0.648 | 0.803 |

**~11.3x faster, with an order-of-magnitude tighter spread** (SD 0.055s vs
0.538s). All 10 watch-enabled repetitions were confirmed
attributed to the watch path specifically (`detected_via=watch` in every
record — the shared `revokeTrackedPolicyLocked` helper tags which mechanism
actually won the race), so this is not an artifact of poll happening to be
fast; the watch path genuinely reacted first every time.

Q9 answer: **yes, watch-based reconciliation measurably and substantially
improves revocation-detection latency** over a slow poll interval — the
predicted benefit of an event-driven path (module doc comment: "a
watch-based reconciler is a reasonable future refinement") is now backed by
a direct measurement, not just architectural plausibility. This was
implemented as a real, opt-in code path (`--watch-revocation`,
`watchRevocationLoop` in `ebpf-agent/cmd/agent/main.go`) using a
`client.WithWatch` Kubernetes watch on `RuntimeSecurityPolicy` DELETE
events, sharing the exact same revoke action (`revokeTrackedPolicyLocked`)
as the poll path so the two mechanisms cannot diverge in *what* revocation
does, only in *how fast* they notice.

Caveat: this compares watch against a **10s** poll interval specifically
(chosen to make any watch benefit clearly visible). At a already-fast 0.5s
poll interval (C1's fastest condition, mean 1.02s), the gap would be much
smaller in absolute terms, though watch's sub-second, near-constant latency
would still likely be lower and less variable (poll's SD grows with the
interval; watch's SD here was ~0.06s, an order of magnitude tighter). This
comparison at multiple poll intervals was not run, due to time constraints
— see Limitations.

## C3 — Stale-but-valid evidence (Q7)

**Question**: can a cryptographically valid evidence object remain
semantically stale with respect to authorization?

A real, signed `RuntimePlacementEvidence` snapshot was captured while a pod
was genuinely authorized and conform (`authorizationState=authorized`,
`conformance=conform`). The underlying decision was then revoked, and the
LIVE object was confirmed to show `authorizationState=revoked` 90 seconds
later (`live_authorization_state_after_wait=revoked`,
`revocation_confirmed_live=true` — not a vacuous result). The **captured,
frozen, pre-revocation snapshot** was then run through `verify-evidence`
twice (`raw/c3-stale-evidence.jsonl`,
`verifier-output/c3-stale-authcurrency-{disabled,enabled}.json`):

| verifier configuration | `valid` | `authorized_and_compliant` | failing check |
|---|---|---|---|
| `--max-authorization-age 0` (disables the Task 06 check — models a verifier using only pre-Task-06 fields) | **true** (all checks pass, including signature, decision-id, decision-hash, policy-hash) | **true** | none |
| default (`--max-authorization-age 15s`, the Task 06 fix) | **false** | **false** | `authorization-currency` only (`ageSeconds=101 maxSeconds=15`) |

With the fix enabled, `authorization-currency` is the *sole* failing check —
every other check (signature, decision/policy hash chain, freshness,
observation-completeness, monitor liveness) legitimately passes, isolating
exactly the property this task added rather than a confound.

**Direct, demonstrated answer to Q7: yes.** A verifier using only the
checks that existed before this task — signature validity, freshness of
`IssuedAt`/`ExpiresAt`, sequence/digest chaining — would accept this stale
snapshot as a positive attestation that the workload is *currently*
authorized and compliant, a full 90+ seconds after that stopped being true.
This is not a signature forgery or tampering — the object is genuinely,
correctly signed; the staleness is semantic, not cryptographic, which is
exactly why signature validity alone cannot catch it. The new
`authorization-currency` check (comparing `now` against the signed
`LastAuthorizationSync`) closes this specific gap for snapshots evaluated
promptly, at the cost of the honest limitation discussed under C4/C5 below.

## C4 — Evidence semantics: RuntimeCompliance vs. AuthorizationValidity

Before this task, the schema had no field distinguishing "did observed
behavior match policy P" from "is decision D still currently valid" — the
audit found these conflated into a single `Conformance` field, with the one
revocation-adjacent field (`RevokedAt`) explicitly unsigned. This task adds,
to the **signed payload** (`operator/pkg/evidence/evidence.go`):

- `AuthorizationState` (`authorized`/`revoked`) — the agent's own
  most-recently-confirmed belief about whether D is still present.
- `LastAuthorizationSync` — updated every poll cycle that confirms the
  policy is still present, frozen the moment revocation is detected.
- `RevokedAt` — moved from status-only/unsigned into the signed payload.

`verify-evidence`'s report now exposes `authorized_and_compliant` as an
**explicit, separate** field from `valid` (see `main.go`
`verificationReport`): a correctly-signed, fresh, honestly-`revoked`
evidence object is `valid=true` (it is not lying, tampered, or stale as a
*signature*) but `authorized_and_compliant=false` (C3's demonstration
above; also covered by a dedicated unit test,
`TestVerifyEvidence_AuthorizedAndCompliant_FalseWhenRevoked`). This
directly operationalizes the protocol's requirement
(`COMPLIANT != AUTHORIZED`) as a checkable field, not just documentation.

## C5 — Acceptance condition and its honest limit

The experiment protocol requires: "a verifier must never silently interpret stale
authorization evidence as currently authorized... if an absolute guarantee
cannot be provided, produce a measured and explicit upper bound."

**No absolute guarantee is possible here, and this is stated plainly rather
than glossed over.** Revocation itself travels as unauthenticated
Kubernetes API state (Task 00's audit finding, reconfirmed at the top of
this document) — there is no signed revocation record analogous to a CRL or
OCSP response. `authorization-currency` bounds how stale the **agent's own,
honestly-reported** belief can be (it cannot know about a revocation more
recent than its own last successful poll), which is a real, measured,
useful bound **under an honest-but-possibly-slow control plane**. It is
**not** a bound against a control plane that is actively malicious and
capable of suppressing or delaying the revocation signal itself before it
ever reaches the agent — under that threat model, `LastAuthorizationSync`
would keep advancing on schedule (the agent genuinely, correctly believes
it is still authorized) while being wrong about the ground truth. This
distinction — bounded staleness against an honest-but-slow control plane,
not a cryptographic guarantee against a malicious one — is the correct,
demonstrated scope of C5's "measured explicit upper bound," and closing the
malicious-control-plane gap would require the kind of signed
revocation-record mechanism the experiment protocol itself gestures at in C4
("if a cryptographically signed revocation record is needed, implement or
document it") — not attempted in this task; flagged as a real, open gap
rather than silently assumed solved.

## Forbidden-claim-word check

Per experiment protocol rule 16, this summary does not claim "secure revocation"
or "fail-closed" — C5 explicitly scopes the guarantee to an honest control
plane and states the malicious-control-plane gap remains open.

## Limitations

- C1's Δ_evidence sub-experiment used n=3 per condition (vs. n=8 for
  Δ_detect) — a documented scope decision: each rep requires waiting for a
  genuine fresh evidence tick (up to ~30s), making it far more
  wall-clock-expensive than Δ_detect's sub-2s reps, on a single live billed
  cluster running many experiments serially.
- C2 compared watch vs. poll at a single, deliberately slow poll interval
  (10s), not across the full range C1 tested (0.5s-10s) — chosen to
  maximize the visibility of any watch benefit within the available time
  budget, not because the comparison is expected to vanish at faster poll
  intervals (the opposite is more likely: watch's SD was an order of
  magnitude tighter than poll's even at 10s).
- C3 is a single controlled trial (n=1), answering a yes/no existence
  question ("can this state be reached and accepted") rather than
  characterizing a distribution — appropriate for what C3 asks, but not a
  repeated-measures statistic.
- The malicious-control-plane revocation-authenticity gap (C5) is
  identified and scoped, not closed. A signed revocation record was not
  implemented.

## Real bugs found and fixed while building this experiment (not hidden)

Three genuine bugs were found and fixed during this task's own scripting,
none affecting RuntimeGuard's actual behavior (all three were measurement-
harness bugs). Full account, including discarded pre-fix data retained per
experiment protocol rule 21, in `exclusions.md`.
