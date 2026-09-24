package controller

import (
	"fmt"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/internal/upstream"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

const PolicyDerivationVersion = "runtime-guard-policy-derivation/v1"

type verifiedDecision struct {
	Token   placementtoken.Token
	Binding aiopsv1alpha1.PlacementBinding
}

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

// applyExecPolicyRequest overlays a signed decision's optional
// ExecPolicyRequest onto material's exec-related fields. A nil request (the
// case for every real article-1-minted token, which never sets this) leaves
// material's existing safe defaults (audit mode, deny-by-default, no
// allowed paths) completely untouched. Invalid enum values are ignored
// (fail safe onto the existing default) rather than propagated, matching the
// CRD's own kubebuilder enum validation for these same fields.
func applyExecPolicyRequest(material *policyHashMaterial, req *placementtoken.ExecPolicyRequest) {
	if req == nil {
		return
	}
	if req.EnforcementMode == "audit" || req.EnforcementMode == "enforce" {
		material.EnforcementMode = req.EnforcementMode
	}
	if req.DefaultAction == "allow" || req.DefaultAction == "deny" {
		material.Exec.DefaultAction = req.DefaultAction
	}
	material.Exec.AllowedPaths = req.AllowedPaths
	material.Exec.DeniedPaths = req.DeniedPaths
}

// applyFilePolicyRequest overlays only file-access fields. Keeping this
// independent from applyExecPolicyRequest is intentional: an exec allow-list
// does not silently broaden file access, while a signed decision can still
// authorize the dynamic-loader libraries or data files its workload needs.
func applyFilePolicyRequest(material *policyHashMaterial, req *placementtoken.FilePolicyRequest) {
	if req == nil {
		return
	}
	if req.DefaultAction == "allow" || req.DefaultAction == "deny" {
		material.FileAccess.DefaultAction = req.DefaultAction
	}
	material.FileAccess.AllowedPathPrefixes = req.AllowedPaths
	material.FileAccess.DeniedPathPrefixes = req.DeniedPaths
}

// applyNetworkPolicyRequest overlays only network-egress fields, same
// independence rationale as applyFilePolicyRequest: exec/file authorization
// does not imply network authorization.
func applyNetworkPolicyRequest(material *policyHashMaterial, req *placementtoken.NetworkPolicyRequest) {
	if req == nil {
		return
	}
	if req.DefaultAction == "allow" || req.DefaultAction == "deny" {
		material.NetworkEgress.DefaultAction = req.DefaultAction
	}
	material.NetworkEgress.AllowedCIDRs = req.AllowedCIDRs
	material.NetworkEgress.DeniedCIDRs = req.DeniedCIDRs
	material.NetworkEgress.AllowedPorts = req.AllowedPorts
}

func (r *AIPlacementDecisionReconciler) derivePolicySpec(decision *upstream.AIPlacementDecision, verified *verifiedDecision) (aiopsv1alpha1.RuntimeSecurityPolicySpec, error) {
	material := policyHashMaterial{
		PlacementDecisionRef: aiopsv1alpha1.ObjectReference{
			Name:      decision.Name,
			Namespace: decision.Namespace,
		},
		TargetRef: aiopsv1alpha1.ObjectReference{
			Name:      decision.Spec.TargetRef.Name,
			Namespace: decision.Spec.TargetRef.Namespace,
		},
		EnforcementMode: "audit",
		Exec: aiopsv1alpha1.ExecPolicy{
			DefaultAction: "deny",
		},
		FileAccess: aiopsv1alpha1.FileAccessPolicy{
			DefaultAction: "deny",
		},
		NetworkEgress: aiopsv1alpha1.NetworkEgressPolicy{
			DefaultAction: "deny",
		},
		DeviceAccess: aiopsv1alpha1.DeviceAccessPolicy{
			DefaultAction: "deny",
		},
		AgentIntegrity: aiopsv1alpha1.AgentIntegritySpec{
			ExpectedImageDigest: r.AgentImageDigest,
		},
	}
	if verified != nil {
		material.Binding = verified.Binding
		applyExecPolicyRequest(&material, verified.Token.Payload.ExecPolicyRequest)
		applyFilePolicyRequest(&material, verified.Token.Payload.FilePolicyRequest)
		applyNetworkPolicyRequest(&material, verified.Token.Payload.NetworkPolicyRequest)
	}

	spec := aiopsv1alpha1.RuntimeSecurityPolicySpec{
		PlacementDecisionRef: material.PlacementDecisionRef,
		TargetRef:            material.TargetRef,
		Binding:              material.Binding,
		EnforcementMode:      material.EnforcementMode,
		Exec:                 material.Exec,
		FileAccess:           material.FileAccess,
		NetworkEgress:        material.NetworkEgress,
		DeviceAccess:         material.DeviceAccess,
		AgentIntegrity:       material.AgentIntegrity,
		BPFLock:              material.BPFLock,
		RevocationTTLSeconds: material.RevocationTTLSeconds,
	}
	if verified == nil {
		return spec, nil
	}

	decisionHash, err := platformcrypto.CanonicalSHA256Hex(verified.Token.Payload)
	if err != nil {
		return aiopsv1alpha1.RuntimeSecurityPolicySpec{}, fmt.Errorf("hash decision payload: %w", err)
	}
	tokenHash, err := platformcrypto.CanonicalSHA256Hex(verified.Token)
	if err != nil {
		return aiopsv1alpha1.RuntimeSecurityPolicySpec{}, fmt.Errorf("hash placement token: %w", err)
	}
	policyHash, err := platformcrypto.CanonicalSHA256Hex(material)
	if err != nil {
		return aiopsv1alpha1.RuntimeSecurityPolicySpec{}, fmt.Errorf("hash derived policy: %w", err)
	}
	spec.Derivation = aiopsv1alpha1.PolicyDerivationTrace{
		DerivationVersion:  PolicyDerivationVersion,
		DecisionHash:       decisionHash,
		PolicyHash:         policyHash,
		EvidenceHash:       verified.Token.Payload.EvidenceHash,
		TokenHash:          tokenHash,
		UpstreamPolicyHash: verified.Token.Payload.PolicyHash,
	}
	return spec, nil
}
