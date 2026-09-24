/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExecPolicy governs execve enforcement for a pod's cgroup.
type ExecPolicy struct {
	// DefaultAction applies to any execve target not matched by AllowedPaths/DeniedPaths.
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=deny
	DefaultAction string `json:"defaultAction"`

	// AllowedPaths lists absolute binary paths permitted to execve.
	// +optional
	AllowedPaths []string `json:"allowedPaths,omitempty"`

	// DeniedPaths lists absolute binary paths explicitly denied, checked before
	// AllowedPaths (deny takes precedence).
	// +optional
	DeniedPaths []string `json:"deniedPaths,omitempty"`
}

// FileAccessPolicy governs file_open enforcement for a pod's cgroup.
type FileAccessPolicy struct {
	// DefaultAction applies to any path not matched by AllowedPathPrefixes/DeniedPathPrefixes.
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=deny
	DefaultAction string `json:"defaultAction"`

	// AllowedPathPrefixes lists path prefixes permitted for file_open (e.g. model
	// weights directory, /tmp scratch space).
	// +optional
	AllowedPathPrefixes []string `json:"allowedPathPrefixes,omitempty"`

	// DeniedPathPrefixes lists path prefixes explicitly denied, checked before
	// AllowedPathPrefixes.
	// +optional
	DeniedPathPrefixes []string `json:"deniedPathPrefixes,omitempty"`
}

// NetworkEgressPolicy governs connect() enforcement for a pod's cgroup.
type NetworkEgressPolicy struct {
	// DefaultAction applies to any destination not matched by AllowedCIDRs/DeniedCIDRs.
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=deny
	DefaultAction string `json:"defaultAction"`

	// AllowedCIDRs lists destination CIDRs permitted for outbound connect().
	// +optional
	AllowedCIDRs []string `json:"allowedCIDRs,omitempty"`

	// AllowedPorts restricts allowed destination ports when set. Empty means any port.
	// +optional
	AllowedPorts []int32 `json:"allowedPorts,omitempty"`

	// DeniedCIDRs lists destination CIDRs explicitly denied, checked before AllowedCIDRs.
	// +optional
	DeniedCIDRs []string `json:"deniedCIDRs,omitempty"`
}

// DeviceAccessPolicy governs device-node access (primarily /dev/nvidia*) for a pod's cgroup.
type DeviceAccessPolicy struct {
	// DefaultAction applies to any device path not matched by AllowedDevicePaths.
	// +kubebuilder:validation:Enum=allow;deny
	// +kubebuilder:default=deny
	DefaultAction string `json:"defaultAction"`

	// AllowedDevicePaths lists device paths this pod is allowed to open
	// (e.g. /dev/nvidia0, /dev/nvidiactl, /dev/nvidia-uvm).
	// +optional
	AllowedDevicePaths []string `json:"allowedDevicePaths,omitempty"`

	// RequireConfidentialGPU mirrors the article 1
	// ConfidentialGPURequirements convention: when true, device access is only
	// conformant if the underlying evidence attests a confidential-computing GPU mode.
	// +optional
	RequireConfidentialGPU bool `json:"requireConfidentialGPU,omitempty"`

	// Vendor identifies the GPU vendor or stack, required when RequireConfidentialGPU is true.
	// +kubebuilder:validation:Enum=nvidia;amd;intel
	// +optional
	Vendor string `json:"vendor,omitempty"`
}

// AgentIntegritySpec captures the Janus-inspired requirement that the eBPF
// agent's own integrity be demonstrated, not assumed: the DaemonSet image is
// pinned by digest, and that digest is verified by the Operator and carried
// into every RuntimePlacementEvidence.
type AgentIntegritySpec struct {
	// ExpectedImageDigest is the pinned agent image reference
	// (repo@sha256:<64 hex chars>) the DaemonSet must run on this node.
	// +kubebuilder:validation:Pattern=`^.+@sha256:[a-f0-9]{64}$`
	ExpectedImageDigest string `json:"expectedImageDigest"`

	// RequireRTMRExtension requests that, on platforms exposing a runtime
	// measurement register (e.g. TDX RTMR), the agent's measurement be
	// extended into it. Documented as a limitation when unavailable rather
	// than silently skipped.
	// +optional
	RequireRTMRExtension bool `json:"requireRTMRExtension,omitempty"`
}

// BPFLockSpec configures the defense-in-depth BPF-lock feature: once the
// agent's own authorized programs are loaded, an LSM hook blocks further BPF
// program loads on the node to close the TOCTOU window on the agent itself.
// Configurable/disablable because it can conflict with other eBPF tooling on
// the cluster (CNI, observability).
type BPFLockSpec struct {
	// Enabled turns on the BPF-lock hook after the agent's authorized programs load.
	// +optional
	Enabled bool `json:"enabled,omitempty"`
}

// PlacementBinding captures the fields copied from the source AIPlacementDecision's
// verified Ed25519 placement token payload (article 1,
// github.com/imperium/ai-sovereign-finops-operator/pkg/token), used to detect
// drift between the signed decision and observed runtime behavior.
type PlacementBinding struct {
	// DecisionID is the immutable signed identity of the source decision.
	// +optional
	DecisionID string `json:"decisionID,omitempty"`

	// DecisionVersion is the signed monotonic version of the source decision.
	// +optional
	DecisionVersion int64 `json:"decisionVersion,omitempty"`

	// DecisionEpoch is the signed monotonic epoch of the source decision.
	// +optional
	DecisionEpoch int64 `json:"decisionEpoch,omitempty"`

	// DecisionNonce is the signed nonce used to reject duplicate decision artifacts.
	// +optional
	DecisionNonce string `json:"decisionNonce,omitempty"`

	// PodUID is the pod UID the placement token was minted for.
	// +optional
	PodUID string `json:"podUID,omitempty"`

	// PodSpecHash is the expected pod spec hash from the placement token payload.
	// +optional
	PodSpecHash string `json:"podSpecHash,omitempty"`

	// ImageDigest is the expected workload image digest from the placement token payload.
	// +optional
	ImageDigest string `json:"imageDigest,omitempty"`

	// ModelDigest is the expected model weights digest from the placement token payload.
	// +optional
	ModelDigest string `json:"modelDigest,omitempty"`

	// NodeIdentity is the expected node identity from the placement token payload.
	// +optional
	NodeIdentity string `json:"nodeIdentity,omitempty"`

	// RuntimeClass is the expected runtime class from the placement token payload.
	// +optional
	RuntimeClass string `json:"runtimeClass,omitempty"`
}

// PolicyDerivationTrace records the deterministic D -> P link and the expected
// evidence digest T carried by the signed placement decision.
type PolicyDerivationTrace struct {
	// DerivationVersion identifies the deterministic policy derivation algorithm.
	// +optional
	DerivationVersion string `json:"derivationVersion,omitempty"`

	// DecisionHash is the SHA-256 digest of canonical JSON for the verified signed decision payload D.
	// +optional
	DecisionHash string `json:"decisionHash,omitempty"`

	// PolicyHash is the SHA-256 digest of canonical JSON for the deterministically derived policy P.
	// +optional
	PolicyHash string `json:"policyHash,omitempty"`

	// EvidenceHash is the expected signed runtime evidence digest T declared by D.
	// +optional
	EvidenceHash string `json:"evidenceHash,omitempty"`

	// TokenHash is the SHA-256 digest of canonical JSON for the complete signed placement token.
	// +optional
	TokenHash string `json:"tokenHash,omitempty"`

	// UpstreamPolicyHash is the policy hash value carried in the signed placement token, if present.
	// +optional
	UpstreamPolicyHash string `json:"upstreamPolicyHash,omitempty"`
}

// +kubebuilder:validation:XValidation:rule="!(has(self.deviceAccess) && has(self.deviceAccess.requireConfidentialGPU) && self.deviceAccess.requireConfidentialGPU) || (has(self.deviceAccess.vendor) && self.deviceAccess.vendor != '')",message="deviceAccess.vendor is required when deviceAccess.requireConfidentialGPU is true"
// +kubebuilder:validation:XValidation:rule="self.enforcementMode != 'enforce' || self.agentIntegrity.expectedImageDigest != ''",message="agentIntegrity.expectedImageDigest is required when enforcementMode is enforce"

// RuntimeSecurityPolicySpec defines the desired state of RuntimeSecurityPolicy.
// One instance is generated per verified AIPlacementDecision from article 1.
type RuntimeSecurityPolicySpec struct {
	// PlacementDecisionRef references the source AIPlacementDecision
	// (aiops.imperium.io/v1alpha1) this policy was derived from.
	PlacementDecisionRef ObjectReference `json:"placementDecisionRef"`

	// TargetRef identifies the workload or pod this policy governs.
	TargetRef ObjectReference `json:"targetRef"`

	// Binding carries the expected fields from the source placement token,
	// used to detect drift between the signed decision and runtime reality.
	// +optional
	Binding PlacementBinding `json:"binding,omitempty"`

	// EnforcementMode controls whether violations are only journaled
	// (audit) or actively blocked (enforce). Must start at "audit" and only
	// move to "enforce" once the mapping and hooks have been validated
	// (Phase 4/5 of the experiment plan).
	// +kubebuilder:validation:Enum=audit;enforce
	// +kubebuilder:default=audit
	EnforcementMode string `json:"enforcementMode"`

	// Exec governs execve enforcement.
	// +optional
	Exec ExecPolicy `json:"exec,omitempty"`

	// FileAccess governs file_open enforcement.
	// +optional
	FileAccess FileAccessPolicy `json:"fileAccess,omitempty"`

	// NetworkEgress governs connect() enforcement.
	// +optional
	NetworkEgress NetworkEgressPolicy `json:"networkEgress,omitempty"`

	// DeviceAccess governs device-node (/dev/nvidia*) enforcement.
	// +optional
	DeviceAccess DeviceAccessPolicy `json:"deviceAccess,omitempty"`

	// AgentIntegrity pins and verifies the eBPF agent's own image digest.
	AgentIntegrity AgentIntegritySpec `json:"agentIntegrity"`

	// Derivation records the deterministic D -> P hash link and expected T hash.
	// +optional
	Derivation PolicyDerivationTrace `json:"derivation,omitempty"`

	// BPFLock configures the defense-in-depth BPF-lock hook.
	// +optional
	BPFLock BPFLockSpec `json:"bpfLock,omitempty"`

	// RevocationTTLSeconds bounds how quickly enforcement must react after a
	// revocation is observed (e.g. from an article 1 AIRevocationPolicy or an
	// equivalent local revocation source). Used to measure the "time to
	// retract rules after revocation" metric (Phase 6).
	// +kubebuilder:validation:Minimum=1
	// +optional
	RevocationTTLSeconds int32 `json:"revocationTTLSeconds,omitempty"`
}

// RuntimeSecurityPolicyStatus defines the observed state of RuntimeSecurityPolicy.
type RuntimeSecurityPolicyStatus struct {
	// ObservedGeneration is the last generation observed by the Operator.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// Decision reflects the outcome of verifying the source AIPlacementDecision's
	// signature/hash before generating this policy.
	// +kubebuilder:validation:Enum=active;rejected;pending
	// +optional
	Decision string `json:"decision,omitempty"`

	// RejectionReason explains a "rejected" Decision (e.g. signature verification failed).
	// +optional
	RejectionReason string `json:"rejectionReason,omitempty"`

	// AgentImageDigestVerified is true once the Operator has confirmed the
	// DaemonSet on the target node runs exactly AgentIntegrity.ExpectedImageDigest.
	// +optional
	AgentImageDigestVerified bool `json:"agentImageDigestVerified,omitempty"`

	// VerificationStatus mirrors the article 1 AttestationEvidence convention.
	// +optional
	VerificationStatus VerificationStatus `json:"verificationStatus,omitempty"`

	// EvidenceMode reflects whether enforcement on the target node is backed
	// by real BPF-LSM enforcement, a simulated/audit-only fallback, or is
	// currently unverified.
	// +optional
	EvidenceMode EvidenceMode `json:"evidenceMode,omitempty"`

	// EnforcementReadyAt is set by the node agent after it successfully applies
	// this policy to the target pod's cgroup maps.
	// +optional
	EnforcementReadyAt *metav1.Time `json:"enforcementReadyAt,omitempty"`

	// EnforcementReadyMonotonicNs is the node-local CLOCK_MONOTONIC_RAW
	// timestamp (nanoseconds since an arbitrary, node-specific epoch) at
	// which the node agent captured EnforcementReadyAt. Unlike
	// EnforcementReadyAt (a metav1.Time, which loses sub-second precision on
	// the wire -- see artifacts/timing/timestamp-semantics.md), this is the
	// authoritative source for t_p in temporal-closure measurements. Only
	// meaningful compared against another CLOCK_MONOTONIC_RAW reading taken
	// on the SAME node; never compare across nodes.
	// +optional
	EnforcementReadyMonotonicNs *int64 `json:"enforcementReadyMonotonicNs,omitempty"`

	// FirstObservedOperationMonotonicNs is the bpf_ktime_get_ns() timestamp
	// (kernel monotonic-since-boot nanoseconds) of the first hook event the
	// node agent observed, via the eBPF ring buffer, for this pod's
	// cgroup(s) since the current policy generation (AppliedPolicyGeneration)
	// was applied. This is t_c: populated exclusively from real eBPF
	// observations, never self-reported by the workload or the launcher (see
	// artifacts/timing/timestamp-semantics.md). Reset to nil whenever a new
	// policy generation is applied to this pod, so a stale prior
	// generation's first-observed timestamp can never be mistaken for the
	// current generation's.
	// +optional
	FirstObservedOperationMonotonicNs *int64 `json:"firstObservedOperationMonotonicNs,omitempty"`

	// AppliedPolicyGeneration is the RuntimeSecurityPolicy generation the node
	// agent last applied to the target cgroup maps.
	// +optional
	AppliedPolicyGeneration int64 `json:"appliedPolicyGeneration,omitempty"`

	// AppliedNodeName is the node whose agent applied this policy.
	// +optional
	AppliedNodeName string `json:"appliedNodeName,omitempty"`

	// AppliedCgroupIDs are the cgroup IDs to which the policy was applied.
	// +optional
	AppliedCgroupIDs []string `json:"appliedCgroupIDs,omitempty"`

	// Conditions captures policy propagation/validation state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=rtsp
//+kubebuilder:printcolumn:name="Mode",type=string,JSONPath=`.spec.enforcementMode`
//+kubebuilder:printcolumn:name="Decision",type=string,JSONPath=`.status.decision`
//+kubebuilder:printcolumn:name="EvidenceMode",type=string,JSONPath=`.status.evidenceMode`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RuntimeSecurityPolicy is the Schema for the runtimesecuritypolicies API
type RuntimeSecurityPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuntimeSecurityPolicySpec   `json:"spec,omitempty"`
	Status RuntimeSecurityPolicyStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// RuntimeSecurityPolicyList contains a list of RuntimeSecurityPolicy
type RuntimeSecurityPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuntimeSecurityPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RuntimeSecurityPolicy{}, &RuntimeSecurityPolicyList{})
}
