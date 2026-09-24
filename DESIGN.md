# DESIGN.md — Article 2 CRDs

This document records the design decisions behind the two CRDs introduced by article 2:
`RuntimeSecurityPolicy` and `RuntimePlacementEvidence`. Both live in the `aiops.imperium.io/v1alpha1`
API group — the same group used by article 1's `AIPlacementDecision`, `AttestationEvidence`, etc.
(repo `github.com/imperium/ai-sovereign-finops-operator`) — so the two articles read as one
coherent platform rather than two unrelated prototypes.

Source of truth for the article 1 contract this design consumes: `EXPERIMENTS_LOG.md`, entry
"Phase 1 — Reprise du contexte de l'article 1" (2026-08-01), which documents the exact
`AIPlacementDecision` CRD schema and the real Ed25519 placement-token format found in
`operateur/pkg/token/token.go` and `operateur/pkg/crypto/` on `origin/main` of that repo.

## Why two CRDs, and what each owns

- **`RuntimeSecurityPolicy`** — desired state. One instance per verified `AIPlacementDecision`.
  Generated *by the Runtime Guard Operator*, never by the node agent. It is the enforcement
  contract: which execve/file_open/connect/device-open behavior is allowed for this specific
  pod's cgroup, plus the pinned, expected digest of the eBPF agent image itself.
- **`RuntimePlacementEvidence`** — observed state. Produced *by the node eBPF agent*, one (or a
  recurring series) per pod, signed Ed25519. It is the audit artifact: what actually happened,
  whether it stayed within the bounds of the policy (the P5 "Runtime Conformance" verdict), and
  whether the agent producing it could prove its own integrity.

Keeping "desired" and "observed" in separate objects, written by separate actors, mirrors the
article 1 split between `ConfidentialInferencePolicy`/`AIPlacementDecision` (desired) and
`AttestationEvidence` (observed) — an operator writes policy objects, evidence objects are never
self-declared by the thing being measured about itself for the *decision* fields, only for the
raw counters/signature.

## Conventions reused from article 1 (not reinvented)

- `ObjectReference{name, namespace?}` for cross-object references.
- `EvidenceMode: real|simulated|unverified` and `VerificationStatus: Verified|Failed|Unavailable`
  — copied verbatim from `AttestationEvidence.status` in article 1. This lets both articles report
  the same real/simulated distinction the same way. In article 2, `EvidenceMode=simulated` is
  the expected value in every kind run and in any AKS run where BPF-LSM turns out inactive
  (Phase 0 found this kernel's WSL2 BPF-LSM is compiled but not in the active LSM chain, so all
  local/kind work starts in this mode; Phase 9 has a mandatory pre-flight check before assuming
  otherwise on AKS).
- `ConfidentialGPURequirements`-style vendor enum (`nvidia;amd;intel`) reused inside
  `DeviceAccessPolicy`.
- Append-only evidence chaining: `RuntimePlacementEvidenceStatus.PreviousEvidenceDigest` mirrors
  `AIEvidenceRecord.spec.previousRecordDigest` from article 1, so a gap or tamper in the sequence
  of evidence for one pod is detectable the same way.
- Revocation: article 1 models revocation as its own object (`AIRevocationPolicy`, with
  `Target`/`EvidenceRef`/`PlacementRef`/`Reasons`/`TTLSeconds`). Article 2 does not duplicate that
  object; instead `RuntimeSecurityPolicySpec.RevocationTTLSeconds` bounds how fast the agent must
  react, and `RuntimePlacementEvidenceStatus.RevokedAt` records when it did — the attack scenario
  "persistence of access after revocation" (Phase 5) and its latency measurement (Phase 6) are
  both expressed through these two fields rather than a new revocation CRD, since article 2 does
  not (yet) originate revocations itself, it only reacts to them.

## The signature contract: what article 2 does *not* invent

Article 1's placement token is signed over `json.Marshal(payload)` of a Go struct (field order is
the struct's declaration order, which `encoding/json` preserves, so no canonicalization is needed
for that one payload). Article 2's `RuntimePlacementEvidence`, by contrast, is a Kubernetes object
whose JSON serialization order is not something we want to depend on for signing. So its
`EvidenceSignature` is defined as: canonicalize a dedicated `operator/pkg/evidence.Payload` with
the shared `CanonicalJSON` helper, SHA-256 it (`PayloadDigest`), then Ed25519-sign the canonical
bytes and hex-encode the signature. The signed payload includes the policy reference, target
reference, `decisionID`, `decisionHash`, `policyHash`, policy generation, monitor identity,
node/pod/cgroup identity, counters, evidence mode, agent image digest, `evidenceSequence`,
`previousEvidenceDigest`, `issuedAt`, and `expiresAt`.

`operator/cmd/verify-evidence` is the independent verifier for this contract. It accepts a
`RuntimePlacementEvidence` snapshot, a `RuntimeSecurityPolicy` snapshot, and the agent public key;
it then reconstructs the signed payload and checks freshness, signature validity, D/P bindings,
monitor identity, target identity, policy generation, pod/node binding, and agent image digest
without consulting or trusting the Operator's internal state.

## Open gap inherited from article 1: public key distribution

Article 1 distributes the scheduler's **private** signing key via a Kubernetes Secret
(`attestation-scheduler-signing-key`, key `privateKeyHex`) or an ephemeral key in kind/dev. There
is no existing mechanism there for distributing the **public** key alone to a third consumer.
Article 2's Runtime Guard Operator needs that public key to verify `AIPlacementDecision` placement
tokens before trusting them.

Decision: rather than granting the Operator RBAC read access to article 1's private-key Secret
(unnecessary privilege for a value that is not secret), article 2 expects the public key to be
published in a plain `ConfigMap` (`attestation-scheduler-public-key`, key `publicKeyHex`) in a
well-known namespace, read via a `--trust-anchor-configmap` flag. Producing that ConfigMap is a
one-line addition to article 1's chart (`PubKeyToHex(pub)` next to the existing Secret template) —
out of scope for this repo, but noted here and in `EXPERIMENTS_LOG.md` since it is a real
integration gap, not a detail to silently paper over.

## Validation strategy: CEL, not a webhook

Both CRDs use `+kubebuilder:validation:XValidation` (CEL) rules for the cross-field invariants that
matter today:
- `deviceAccess.requireConfidentialGPU` implies `deviceAccess.vendor` is set.
- `enforcementMode: enforce` implies `agentIntegrity.expectedImageDigest` is set (you cannot
  enforce without having pinned what you expect to be running).

A validating admission webhook was deliberately *not* scaffolded for Phase 2. Everything CEL can
express in-schema, at zero extra runtime/infra cost, worked and needed on both kind and AKS
identically) is preferable to standing up webhook TLS/cert-manager machinery this early. A webhook
becomes justified only if a future rule needs to consult live cluster state that CEL cannot see
(e.g. checking the referenced `AIPlacementDecision` actually exists at admission time) — revisit in
Phase 3 if the Operator's reconcile loop turns out to need that check enforced earlier than
reconcile time.

## Field-level notes

- `RuntimePlacementEvidenceStatus.CgroupID` is a numeric **string**, not an integer: cgroup v2 IDs
  are `uint64` and JSON/YAML numeric handling in various client libraries loses precision above
  2^53 — a real, previously-seen class of bug, not speculative.
- `RuntimePlacementEvidenceStatus.DecisionHash`, `PolicyHash`, and `PreviousEvidenceDigest` are
  lowercase SHA-256 hex strings. `EvidenceSequence` is the per-policy monotonic freshness counter;
  together with `IssuedAt`/`ExpiresAt`, it lets the external verifier compute `G_E(t)` and reject
  stale evidence.
- `AgentIntegritySpec.ExpectedImageDigest` / `AgentIntegrityObserved.ImageDigest` are validated by
  regex (`^.+@sha256:[a-f0-9]{64}$`) so a malformed or tag-only (non-digest) reference is rejected
  by the API server itself, not caught late in a controller.
- Both CRDs default `EnforcementMode`/`DefaultAction` fields to the safe, non-blocking option
  (`audit` / `deny`-only-with-empty-allowlist-having-no-effect-until-populated) — consistent with
  Phase 4's requirement to start strictly audit-only.

## Toolchain note

This repo's Go toolchain (1.25.8) cannot build the kubebuilder-pinned `controller-gen`/`kustomize`
versions from source (`golang.org/x/tools@v0.16.1`, a transitive dependency of the old pinned
`controller-gen`, fails under Go 1.22+'s stricter constant-overflow checking — a known upstream
issue, not specific to this machine). System-installed `controller-gen` (v0.14.0, matching the
Makefile's pinned version exactly) and `kustomize` were used directly instead of `make manifests`/
`make generate`'s auto-download path. See `EXPERIMENTS_LOG.md` Phase 2 entry and `README.md` for
the exact commands a reviewer needs to reproduce this.
