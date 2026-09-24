// Package token decodes and verifies the Ed25519-signed placement tokens
// minted by article 1's attestation scheduler
// (github.com/imperium/ai-sovereign-finops-operator/pkg/token). Article 2
// does not mint these tokens — only article 1's scheduler does — it only
// needs to verify one before trusting the AIPlacementDecision it rode in on.
// The Payload field set, JSON tags, and signing scheme (Ed25519 over
// json.Marshal(payload), hex-encoded) are copied field-for-field from the
// real object observed in that repo (see EXPERIMENTS_LOG.md, Phase 1) so this
// package can verify tokens article 1 actually produces, not an invented format.
package token

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
)

// AnnotationKey is the annotation article 1's scheduler writes the encoded
// Token to on the AIPlacementDecision object.
const AnnotationKey = "ai.sovereign.io/placement-token"

// ExecPolicyRequest lets a signed decision optionally request specific
// execve enforcement for the workload it authorizes, so derive(D) (see
// internal/controller/policy_derivation.go) has something workload-specific
// to turn into RuntimeSecurityPolicy.Spec.Exec instead of always falling
// back to the fixed audit/deny-everything default. Entirely optional and
// additive: omitted (nil) for every real article-1-minted token, which never
// sets it, and its `omitempty` field tags mean an absent request produces
// byte-identical JSON to before this field existed -- real tokens' signatures
// are unaffected.
type ExecPolicyRequest struct {
	// EnforcementMode is "audit" or "enforce"; empty means "audit" (derive(D)'s
	// existing safe default, unchanged).
	EnforcementMode string `json:"enforcement_mode,omitempty"`
	// DefaultAction is "allow" or "deny"; empty means "deny" (unchanged default).
	DefaultAction string `json:"default_action,omitempty"`
	// AllowedPaths/DeniedPaths mirror RuntimeSecurityPolicySpec.Exec's fields
	// of the same name.
	AllowedPaths []string `json:"allowed_exec_paths,omitempty"`
	DeniedPaths  []string `json:"denied_exec_paths,omitempty"`
}

// FilePolicyRequest lets the signed decision describe the file reads/writes
// that the authorized workload needs in addition to its exec policy. This is
// deliberately separate from ExecPolicyRequest: allowing a binary to execute
// must not implicitly grant that process unrestricted file access. Dynamic
// binaries therefore need their loader/runtime dependencies listed here (or
// an explicitly signed allow-by-default file policy).
//
// Like ExecPolicyRequest, this is optional and additive. When omitted, its
// omitempty tag preserves the exact JSON bytes produced for legacy article-1
// payloads and for existing exec-only test payloads.
type FilePolicyRequest struct {
	// DefaultAction is "allow" or "deny"; empty means "deny" (unchanged default).
	DefaultAction string `json:"default_action,omitempty"`
	// The current BPF map implements exact canonical-path matches even though
	// the v1alpha1 CRD field it feeds is historically named *PathPrefixes.
	// Keep this signed request honest about the implemented semantics.
	AllowedPaths []string `json:"allowed_file_paths,omitempty"`
	DeniedPaths  []string `json:"denied_file_paths,omitempty"`
}

// NetworkPolicyRequest lets the signed decision describe the outbound
// connect() destinations the authorized workload needs, independently of its
// exec/file policy for the same reason as FilePolicyRequest: being allowed to
// run does not imply unrestricted egress. AllowedCIDRs/DeniedCIDRs and
// AllowedPorts mirror RuntimeSecurityPolicySpec.NetworkEgress's fields of the
// same name (see policy.go's netRulesForCIDR doc comment: only /32 exact
// hosts are actually enforced today, wider CIDRs are accepted but skipped
// with a logged warning, not silently widened).
//
// Optional and additive, same as ExecPolicyRequest/FilePolicyRequest: omitted
// (nil) preserves byte-identical JSON for any payload that does not set it.
type NetworkPolicyRequest struct {
	// DefaultAction is "allow" or "deny"; empty means "deny" (unchanged default).
	DefaultAction string   `json:"default_action,omitempty"`
	AllowedCIDRs  []string `json:"allowed_cidrs,omitempty"`
	DeniedCIDRs   []string `json:"denied_cidrs,omitempty"`
	AllowedPorts  []int32  `json:"allowed_ports,omitempty"`
}

// Payload holds all verifiable fields of a placement token. Field order and
// JSON tags for every field EXCEPT the optional policy requests must match
// article 1's pkg/token.Payload exactly: the signature is computed over
// json.Marshal(payload), so any divergence there would make every real token
// fail verification. The policy requests are article-2-only; their doc
// comments explain why adding omitted fields preserves legacy signatures.
type Payload struct {
	DecisionID           string                `json:"decision_id"`
	DecisionVersion      int64                 `json:"decision_version"`
	DecisionEpoch        int64                 `json:"decision_epoch"`
	DecisionNonce        string                `json:"decision_nonce"`
	PodUID               string                `json:"pod_uid"`
	PodSpecHash          string                `json:"pod_spec_hash"`
	ImageDigest          string                `json:"image_digest"`
	ModelDigest          string                `json:"model_digest"`
	NodeIdentity         string                `json:"node_identity"`
	GPUIdentity          string                `json:"gpu_identity,omitempty"`
	RuntimeClass         string                `json:"runtime_class"`
	EvidenceHash         string                `json:"evidence_hash"`
	PolicyHash           string                `json:"policy_hash"`
	KeyIdentifier        string                `json:"key_identifier,omitempty"`
	IssuedAt             int64                 `json:"issued_at"`
	ExpiresAt            int64                 `json:"expires_at"`
	ExecPolicyRequest    *ExecPolicyRequest    `json:"exec_policy_request,omitempty"`
	FilePolicyRequest    *FilePolicyRequest    `json:"file_policy_request,omitempty"`
	NetworkPolicyRequest *NetworkPolicyRequest `json:"network_policy_request,omitempty"`
}

// Token is a signed placement token.
type Token struct {
	Payload   Payload `json:"payload"`
	Signature string  `json:"signature"`
}

// Decode parses a JSON-encoded token, as found in the AnnotationKey annotation.
func Decode(raw string) (Token, error) {
	var tok Token
	if err := json.Unmarshal([]byte(raw), &tok); err != nil {
		return Token{}, fmt.Errorf("decode token: %w", err)
	}
	return tok, nil
}

// Verify checks the token signature and expiry against the scheduler's
// public key. It returns an error describing why verification failed, or nil
// if the token is valid.
func Verify(pub ed25519.PublicKey, tok Token) error {
	if pub == nil {
		return fmt.Errorf("public key is nil")
	}
	if strings.TrimSpace(tok.Payload.DecisionID) == "" {
		return fmt.Errorf("decision_id is required")
	}
	if tok.Payload.DecisionVersion < 1 {
		return fmt.Errorf("decision_version must be >= 1")
	}
	if tok.Payload.DecisionEpoch < 1 {
		return fmt.Errorf("decision_epoch must be >= 1")
	}
	if strings.TrimSpace(tok.Payload.DecisionNonce) == "" {
		return fmt.Errorf("decision_nonce is required")
	}
	if tok.Payload.IssuedAt <= 0 {
		return fmt.Errorf("issued_at is required")
	}
	if tok.Payload.ExpiresAt <= tok.Payload.IssuedAt {
		return fmt.Errorf("expires_at must be after issued_at")
	}
	if time.Now().UTC().Unix() > tok.Payload.ExpiresAt {
		return fmt.Errorf("token expired")
	}
	data, err := json.Marshal(tok.Payload)
	if err != nil {
		return fmt.Errorf("marshal token payload for verification: %w", err)
	}
	ok, err := platformcrypto.Ed25519Verify(pub, data, tok.Signature)
	if err != nil {
		return fmt.Errorf("verify token signature: %w", err)
	}
	if !ok {
		return fmt.Errorf("token signature invalid")
	}
	return nil
}

// VerifyForPod checks the token signature/expiry and, when the corresponding
// expected value is non-empty, that the token's fields match the runtime
// context the Runtime Guard Operator observed (pod UID, pod spec hash, node
// identity, evidence hash, policy hash). A mismatch here is exactly the drift
// P5 (Runtime Conformance) is meant to catch between the signed decision and
// reality.
func VerifyForPod(pub ed25519.PublicKey, tok Token, podUID, podSpecHash, nodeIdentity, evidenceHash, policyHash string) error {
	if err := Verify(pub, tok); err != nil {
		return err
	}
	if strings.TrimSpace(podUID) != "" && tok.Payload.PodUID != podUID {
		return fmt.Errorf("pod UID mismatch: token=%q request=%q", tok.Payload.PodUID, podUID)
	}
	if podSpecHash != "" && tok.Payload.PodSpecHash != podSpecHash {
		return fmt.Errorf("pod spec hash mismatch")
	}
	if nodeIdentity != "" && tok.Payload.NodeIdentity != nodeIdentity {
		return fmt.Errorf("node identity mismatch")
	}
	if evidenceHash != "" && tok.Payload.EvidenceHash != evidenceHash {
		return fmt.Errorf("evidence hash mismatch")
	}
	if policyHash != "" && tok.Payload.PolicyHash != policyHash {
		return fmt.Errorf("policy hash mismatch")
	}
	return nil
}
