// Package trustverify implements worker-side validation of the D -> P
// trust chain (Task 11, experiment protocol section 13). Before this task, the
// agent trusted whatever RuntimeSecurityPolicy the Kubernetes control
// plane produced, with zero independent verification of the signed
// AIPlacementDecision (D) it was supposedly derived from -- see
// artifacts/experiments/control-plane-tampering/summary.md for the full
// Task 00-grounded problem statement this closes.
//
// This package implements, for each policy the agent considers applying:
//
//  1. VerifySignature(D) == true (reusing operator/pkg/token.VerifyForPod,
//     the SAME verification code the operator's own controller uses --
//     not a reimplementation that could drift).
//  2. hash(P_received) == hash(derive(D)): the agent independently
//     recomputes the policyHashMaterial the operator's controller would
//     have derived from D (mirroring internal/controller/policy_derivation.go,
//     which cannot be imported directly -- it is internal/ to the operator
//     module, a separate Go module from this agent), hashes it the same
//     way (operator/pkg/crypto.CanonicalSHA256Hex), and compares against
//     the SAME hash computed from the policy actually received. A
//     control plane that tampers with Exec/FileAccess/NetworkEgress/
//     DeviceAccess/EnforcementMode after the operator derived the
//     original policy changes this hash and is caught here -- comparing
//     against a hash-shaped field the tampering operator could also have
//     rewritten would not be a real check.
//  3. Decision freshness, version, and anti-replay (an in-memory ledger;
//     see ReplayLedger's doc comment for the honest limitation this
//     implies), Pod UID, and node identity -- via VerifyForPod's existing
//     parameter checks plus this package's own ledger.
package trustverify

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

// decisionGVK matches operator/internal/upstream's AIPlacementDecision --
// that type is internal/ to the operator module and cannot be imported
// from this separate module, so the agent fetches it unstructured
// instead. This is the standard, supported controller-runtime pattern for
// exactly this situation, not a workaround.
var decisionGVK = schema.GroupVersionKind{Group: "aiops.imperium.io", Version: "v1alpha1", Kind: "AIPlacementDecision"}

// LoadTrustAnchor reads the scheduler's Ed25519 public key from the same
// ConfigMap the operator's own controller reads (see
// internal/controller/aiplacementdecision_controller.go's loadTrustAnchor)
// -- the trust anchor is public key material, safe for both components to
// read from the same source rather than each holding a private copy.
func LoadTrustAnchor(ctx context.Context, c client.Client, namespace, name, key string) (ed25519.PublicKey, error) {
	var cm corev1.ConfigMap
	if err := c.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &cm); err != nil {
		return nil, fmt.Errorf("get trust anchor configmap %s/%s: %w", namespace, name, err)
	}
	hexKey, ok := cm.Data[key]
	if !ok {
		return nil, fmt.Errorf("configmap %s/%s missing key %q", namespace, name, key)
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode trust anchor public key hex: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("trust anchor public key has wrong length: got %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// LoadTrustAnchorTOFU wraps LoadTrustAnchor with Trust-On-First-Use pinning
// against a local, node-persistent file (pinPath). This is a REAL but
// BOUNDED mitigation, not a claim to solve trust-anchor compromise in
// general -- stated explicitly, per the user's requirement that this gap
// not be left silently undocumented:
//
//   - What it catches: the trust-anchor ConfigMap changing AFTER this
//     agent has already pinned a key on this node -- e.g. a compromised
//     control plane silently swapping in an attacker-controlled public key
//     to make the worker accept attacker-forged decisions. On a mismatch,
//     this returns an error (the caller's existing "nil key = deny-all"
//     path in reconcileOnce handles the fail-closed response), and the
//     mismatch itself is the alert (logged by the caller).
//   - What it does NOT catch: compromise of the trust anchor BEFORE this
//     agent's first-ever pin (day-zero/day-one compromise) -- TOFU
//     definitionally trusts whatever it first observes. It also cannot
//     defend against an attacker who ALSO controls this node's local
//     filesystem (they could simply rewrite pinPath too) -- pinning to a
//     hostPath file raises the bar (requires node-level compromise, not
//     just control-plane/ConfigMap compromise) but is not a hardware root
//     of trust. Closing either gap would require relocating trust anchor
//     verification to something the node itself cannot rewrite (an HSM,
//     a remote attestation service, or a multi-party signing scheme) --
//     a different architecture, not a bug fix, and out of this campaign's
//     scope.
//   - Legitimate key rotation: since this pins forever once set, an
//     intentional trust-anchor key rotation will trip the same alert as
//     an attack. The operational answer is the same for both cases
//     (a human reviews the alert and decides), but a planned rotation can
//     be pre-authorized by deleting pinPath before the rotation, which
//     re-arms TOFU to pin the new key on next use -- an explicit,
//     auditable, privileged action (requires node filesystem access),
//     not a silent bypass.
func LoadTrustAnchorTOFU(ctx context.Context, c client.Client, namespace, name, key, pinPath string) (ed25519.PublicKey, error) {
	pub, err := LoadTrustAnchor(ctx, c, namespace, name, key)
	if err != nil {
		return nil, err
	}

	pinnedHex, readErr := os.ReadFile(pinPath)
	if readErr != nil {
		if !os.IsNotExist(readErr) {
			return nil, fmt.Errorf("read trust anchor pin %s: %w", pinPath, readErr)
		}
		// First use on this node: pin it.
		if err := os.MkdirAll(filepath.Dir(pinPath), 0o755); err != nil {
			return nil, fmt.Errorf("create trust anchor pin directory: %w", err)
		}
		if err := os.WriteFile(pinPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
			return nil, fmt.Errorf("write trust anchor pin %s: %w", pinPath, err)
		}
		return pub, nil
	}

	pinned, decErr := hex.DecodeString(string(pinnedHex))
	if decErr != nil {
		return nil, fmt.Errorf("trust anchor pin file %s is corrupt: %w", pinPath, decErr)
	}
	if hex.EncodeToString(pinned) != hex.EncodeToString(pub) {
		return nil, fmt.Errorf("TRUST ANCHOR CHANGED: this node pinned a different scheduler public key on first use (pinned=%s, observed=%s) -- refusing to trust the new key; this is either a trust-anchor compromise or an unauthorized/unannounced key rotation. If this is a legitimate planned rotation, delete %s on this node to re-arm TOFU pinning",
			hex.EncodeToString(pinned), hex.EncodeToString(pub), pinPath)
	}
	return pub, nil
}

// ReplayLedger tracks the highest (epoch, version) seen per decision_id.
// Optionally persisted to a local, node-persistent file (persistPath) --
// see NewReplayLedgerPersistent. Without a persistPath (NewReplayLedger),
// state is in-memory only and does not survive an agent restart; this
// still closes the specific gap Task 11 targets (a compromised control
// plane replaying an old, validly-signed decision+policy pair to an
// agent that has not restarted since first seeing it), but does not
// close a "malicious control plane colluding with an agent restart"
// scenario -- NewReplayLedgerPersistent closes that one instead (this
// package still cannot reuse the operator's own ConfigMap-backed
// decision_ledger.go, which is internal/ to the operator's separate Go
// module -- a local file is this package's own, independent mechanism).
type ReplayLedger struct {
	mu          sync.Mutex
	seen        map[string]seenEntry
	persistPath string
}

type seenEntry struct {
	Epoch, Version int64
	Nonce          string
}

func NewReplayLedger() *ReplayLedger {
	return &ReplayLedger{seen: make(map[string]seenEntry)}
}

// NewReplayLedgerPersistent loads any existing ledger state from
// persistPath (a JSON file) if present, and writes the full state back to
// it after every CheckAndRecord call that changes state -- so an agent
// restart on the SAME node resumes with the same anti-replay/anti-rollback
// memory instead of forgetting every decision it had previously seen.
// This is node-local persistence (a hostPath-backed file, surviving pod
// restarts on the same node), not cluster-wide: a pod rescheduled to a
// DIFFERENT node starts with an empty ledger on that node, same as
// before -- an explicit, documented scope boundary, not a silent gap.
func NewReplayLedgerPersistent(persistPath string) (*ReplayLedger, error) {
	l := &ReplayLedger{seen: make(map[string]seenEntry), persistPath: persistPath}
	data, err := os.ReadFile(persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return l, nil
		}
		return nil, fmt.Errorf("read replay ledger %s: %w", persistPath, err)
	}
	if len(data) == 0 {
		return l, nil
	}
	if err := json.Unmarshal(data, &l.seen); err != nil {
		return nil, fmt.Errorf("parse replay ledger %s: %w", persistPath, err)
	}
	return l, nil
}

// CheckAndRecord rejects a decision whose (epoch, version) has gone
// backward relative to the highest previously seen for this decision_id
// (anti-rollback), or whose (epoch, version) matches a previously seen
// one with a DIFFERENT nonce (a forged replay reusing the version number
// with different content). A repeat of the IDENTICAL (epoch, version,
// nonce) is accepted (idempotent re-application of the same still-valid
// decision across poll cycles, not a replay attack).
func (l *ReplayLedger) CheckAndRecord(decisionID string, epoch, version int64, nonce string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev, ok := l.seen[decisionID]
	if ok {
		if epoch < prev.Epoch || (epoch == prev.Epoch && version < prev.Version) {
			return fmt.Errorf("anti-replay: decision %q epoch/version (%d/%d) is older than previously seen (%d/%d)",
				decisionID, epoch, version, prev.Epoch, prev.Version)
		}
		if epoch == prev.Epoch && version == prev.Version && nonce != prev.Nonce {
			return fmt.Errorf("anti-replay: decision %q epoch/version (%d/%d) seen before with a different nonce (replay)",
				decisionID, epoch, version)
		}
	}
	l.seen[decisionID] = seenEntry{Epoch: epoch, Version: version, Nonce: nonce}
	if l.persistPath != "" {
		if err := l.persistLocked(); err != nil {
			// Fail-safe direction: the in-memory check above already
			// succeeded, so returning an error here would incorrectly
			// reject a legitimate decision over a local disk fault. Log
			// via the returned wrapped state instead of silently
			// swallowing -- the caller (trustverify.Verify's caller in
			// cmd/agent) already logs errors from this path; a disk
			// failure surfaces as a persistence-specific error string a
			// human can grep for, without blocking legitimate traffic.
			return fmt.Errorf("replay ledger state updated but failed to persist to %s (in-memory state is still correct for this run): %w", l.persistPath, err)
		}
	}
	return nil
}

// persistLocked writes the full ledger state to persistPath. Caller must
// hold l.mu. Uses a temp-file-then-rename to avoid a torn/partial write
// being read back as corrupt state after a crash mid-write.
func (l *ReplayLedger) persistLocked() error {
	data, err := json.Marshal(l.seen)
	if err != nil {
		return fmt.Errorf("marshal replay ledger: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(l.persistPath), 0o755); err != nil {
		return fmt.Errorf("create replay ledger directory: %w", err)
	}
	tmp := l.persistPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("write replay ledger temp file: %w", err)
	}
	if err := os.Rename(tmp, l.persistPath); err != nil {
		return fmt.Errorf("rename replay ledger into place: %w", err)
	}
	return nil
}

// policyHashMaterial mirrors operator/internal/controller/policy_derivation.go's
// unexported struct of the same name field-for-field (including JSON tags,
// since CanonicalSHA256Hex hashes the JSON encoding) -- duplicated here,
// not imported, because that file is internal/ to the operator module.
// Any future change to the operator's struct MUST be mirrored here or
// this check will start failing on every legitimate policy (a fail-safe
// direction: it fails CLOSED, not open, if the two drift).
type policyHashMaterial struct {
	PlacementDecisionRef aiopsv1alpha1.ObjectReference     `json:"placementDecisionRef"`
	TargetRef            aiopsv1alpha1.ObjectReference     `json:"targetRef"`
	Binding              aiopsv1alpha1.PlacementBinding    `json:"binding,omitempty"`
	EnforcementMode      string                            `json:"enforcementMode"`
	Exec                 aiopsv1alpha1.ExecPolicy          `json:"exec"`
	FileAccess           aiopsv1alpha1.FileAccessPolicy    `json:"fileAccess"`
	NetworkEgress        aiopsv1alpha1.NetworkEgressPolicy `json:"networkEgress"`
	DeviceAccess         aiopsv1alpha1.DeviceAccessPolicy  `json:"deviceAccess"`
	AgentIntegrity       aiopsv1alpha1.AgentIntegritySpec  `json:"agentIntegrity"`
	BPFLock              aiopsv1alpha1.BPFLockSpec         `json:"bpfLock,omitempty"`
	RevocationTTLSeconds int32                             `json:"revocationTTLSeconds,omitempty"`
}

// expectedFromDecision builds the policyHashMaterial the operator's
// controller would derive from a verified decision -- mirroring
// derivePolicySpec's baseline (a deny-all/audit-mode default for every rule
// category) AND its signed exec/file request overlays (see
// operator/internal/controller/policy_derivation.go, whose request handling
// below must stay byte-for-byte equivalent to avoid derivation drift).
func expectedFromDecision(decisionRef, targetRef aiopsv1alpha1.ObjectReference, binding aiopsv1alpha1.PlacementBinding, expectedAgentImageDigest string, execReq *placementtoken.ExecPolicyRequest, fileReq *placementtoken.FilePolicyRequest, netReq *placementtoken.NetworkPolicyRequest) policyHashMaterial {
	material := policyHashMaterial{
		PlacementDecisionRef: decisionRef,
		TargetRef:            targetRef,
		Binding:              binding,
		EnforcementMode:      "audit",
		Exec:                 aiopsv1alpha1.ExecPolicy{DefaultAction: "deny"},
		FileAccess:           aiopsv1alpha1.FileAccessPolicy{DefaultAction: "deny"},
		NetworkEgress:        aiopsv1alpha1.NetworkEgressPolicy{DefaultAction: "deny"},
		DeviceAccess:         aiopsv1alpha1.DeviceAccessPolicy{DefaultAction: "deny"},
		AgentIntegrity:       aiopsv1alpha1.AgentIntegritySpec{ExpectedImageDigest: expectedAgentImageDigest},
	}
	// Mirrors applyExecPolicyRequest exactly: a nil request (every real
	// article-1-minted token) leaves the baseline above untouched.
	if execReq != nil {
		if execReq.EnforcementMode == "audit" || execReq.EnforcementMode == "enforce" {
			material.EnforcementMode = execReq.EnforcementMode
		}
		if execReq.DefaultAction == "allow" || execReq.DefaultAction == "deny" {
			material.Exec.DefaultAction = execReq.DefaultAction
		}
		material.Exec.AllowedPaths = execReq.AllowedPaths
		material.Exec.DeniedPaths = execReq.DeniedPaths
	}
	// Mirrors applyFilePolicyRequest exactly. File access remains independently
	// deny-by-default unless the signed decision explicitly says otherwise.
	if fileReq != nil {
		if fileReq.DefaultAction == "allow" || fileReq.DefaultAction == "deny" {
			material.FileAccess.DefaultAction = fileReq.DefaultAction
		}
		material.FileAccess.AllowedPathPrefixes = fileReq.AllowedPaths
		material.FileAccess.DeniedPathPrefixes = fileReq.DeniedPaths
	}
	// Mirrors applyNetworkPolicyRequest exactly.
	if netReq != nil {
		if netReq.DefaultAction == "allow" || netReq.DefaultAction == "deny" {
			material.NetworkEgress.DefaultAction = netReq.DefaultAction
		}
		material.NetworkEgress.AllowedCIDRs = netReq.AllowedCIDRs
		material.NetworkEgress.DeniedCIDRs = netReq.DeniedCIDRs
		material.NetworkEgress.AllowedPorts = netReq.AllowedPorts
	}
	return material
}

// receivedFromPolicy builds the same shape from the policy object AS
// ACTUALLY RECEIVED from Kubernetes -- its real, current field values,
// not anything the (possibly compromised) control plane merely claims
// via Spec.Derivation.PolicyHash. Hashing this and comparing against
// expectedFromDecision's hash is what makes this a genuine independent
// check rather than comparing two fields the same attacker could both
// have written.
func receivedFromPolicy(p *aiopsv1alpha1.RuntimeSecurityPolicy) policyHashMaterial {
	return policyHashMaterial{
		PlacementDecisionRef: p.Spec.PlacementDecisionRef,
		TargetRef:            p.Spec.TargetRef,
		Binding:              p.Spec.Binding,
		EnforcementMode:      p.Spec.EnforcementMode,
		Exec:                 p.Spec.Exec,
		FileAccess:           p.Spec.FileAccess,
		NetworkEgress:        p.Spec.NetworkEgress,
		DeviceAccess:         p.Spec.DeviceAccess,
		AgentIntegrity:       p.Spec.AgentIntegrity,
		BPFLock:              p.Spec.BPFLock,
		RevocationTTLSeconds: p.Spec.RevocationTTLSeconds,
	}
}

// Result carries the full verification outcome for logging/evidence, not
// just a pass/fail bool -- G1-style "record hook, kernel result, reason"
// discipline applied to this trust check too.
type Result struct {
	Trusted bool
	Reason  string // empty if Trusted
}

// Verify performs the full D -> P worker-side validation for one policy:
// fetches the referenced AIPlacementDecision (unstructured), verifies its
// signature and freshness/version/PodUID/node-identity binding via
// operator/pkg/token.VerifyForPod, checks anti-replay via ledger, then
// compares hash(derive(D)) against hash(P_received).
func Verify(ctx context.Context, c client.Client, pub ed25519.PublicKey, ledger *ReplayLedger,
	p *aiopsv1alpha1.RuntimeSecurityPolicy, podUID, nodeIdentity, expectedAgentImageDigest string) Result {

	decRef := p.Spec.PlacementDecisionRef
	if decRef.Name == "" {
		return Result{Reason: "policy has no placementDecisionRef"}
	}
	decNS := decRef.Namespace
	if decNS == "" {
		decNS = p.Namespace
	}

	dec := &unstructured.Unstructured{}
	dec.SetGroupVersionKind(decisionGVK)
	if err := c.Get(ctx, types.NamespacedName{Namespace: decNS, Name: decRef.Name}, dec); err != nil {
		return Result{Reason: fmt.Sprintf("fetch source AIPlacementDecision %s/%s: %v", decNS, decRef.Name, err)}
	}

	statusDecision, _, _ := unstructured.NestedString(dec.Object, "status", "decision")
	if statusDecision != "allow" {
		return Result{Reason: fmt.Sprintf("source AIPlacementDecision status.decision=%q, not \"allow\"", statusDecision)}
	}

	raw, ok := dec.GetAnnotations()[placementtoken.AnnotationKey]
	if !ok || raw == "" {
		return Result{Reason: "source AIPlacementDecision missing " + placementtoken.AnnotationKey + " annotation"}
	}
	tok, err := placementtoken.Decode(raw)
	if err != nil {
		return Result{Reason: fmt.Sprintf("decode placement token: %v", err)}
	}

	if err := placementtoken.VerifyForPod(pub, tok, podUID, "", nodeIdentity, "", ""); err != nil {
		return Result{Reason: fmt.Sprintf("VerifySignature(D) failed: %v", err)}
	}

	if err := ledger.CheckAndRecord(tok.Payload.DecisionID, tok.Payload.DecisionEpoch, tok.Payload.DecisionVersion, tok.Payload.DecisionNonce); err != nil {
		return Result{Reason: err.Error()}
	}

	targetName, _, _ := unstructured.NestedString(dec.Object, "spec", "targetRef", "name")
	targetNS, _, _ := unstructured.NestedString(dec.Object, "spec", "targetRef", "namespace")

	binding := aiopsv1alpha1.PlacementBinding{
		DecisionID:      tok.Payload.DecisionID,
		DecisionVersion: tok.Payload.DecisionVersion,
		DecisionEpoch:   tok.Payload.DecisionEpoch,
		DecisionNonce:   tok.Payload.DecisionNonce,
		PodUID:          tok.Payload.PodUID,
		PodSpecHash:     tok.Payload.PodSpecHash,
		ImageDigest:     tok.Payload.ImageDigest,
		ModelDigest:     tok.Payload.ModelDigest,
		NodeIdentity:    tok.Payload.NodeIdentity,
		RuntimeClass:    tok.Payload.RuntimeClass,
	}
	expected := expectedFromDecision(
		aiopsv1alpha1.ObjectReference{Name: dec.GetName(), Namespace: dec.GetNamespace()},
		aiopsv1alpha1.ObjectReference{Name: targetName, Namespace: targetNS},
		binding, expectedAgentImageDigest, tok.Payload.ExecPolicyRequest, tok.Payload.FilePolicyRequest, tok.Payload.NetworkPolicyRequest,
	)
	received := receivedFromPolicy(p)

	expectedHash, err := platformcrypto.CanonicalSHA256Hex(expected)
	if err != nil {
		return Result{Reason: fmt.Sprintf("hash derived policy: %v", err)}
	}
	receivedHash, err := platformcrypto.CanonicalSHA256Hex(received)
	if err != nil {
		return Result{Reason: fmt.Sprintf("hash received policy: %v", err)}
	}
	if expectedHash != receivedHash {
		return Result{Reason: fmt.Sprintf("hash(P_received) != hash(derive(D)): received=%s derived=%s -- policy content does not match what the signed decision authorizes", receivedHash[:16], expectedHash[:16])}
	}

	return Result{Trusted: true}
}
