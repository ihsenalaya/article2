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

// ObservedBehaviorCounters accumulates hook observations for a pod's cgroup
// since the last evidence emission. Counters, not full traces, keep the CRD
// lightweight; raw traces (if enabled) go to the agent's own logs, not the CRD.
type ObservedBehaviorCounters struct {
	// ExecAllowed counts execve calls permitted by policy.
	// +optional
	ExecAllowed int64 `json:"execAllowed,omitempty"`
	// ExecDenied counts execve calls denied by policy (or that would have been
	// denied, in audit mode).
	// +optional
	ExecDenied int64 `json:"execDenied,omitempty"`

	// FileOpenAllowed counts file_open calls permitted by policy.
	// +optional
	FileOpenAllowed int64 `json:"fileOpenAllowed,omitempty"`
	// FileOpenDenied counts file_open calls denied by policy (or that would
	// have been denied, in audit mode).
	// +optional
	FileOpenDenied int64 `json:"fileOpenDenied,omitempty"`

	// ConnectAllowed counts connect() calls permitted by policy.
	// +optional
	ConnectAllowed int64 `json:"connectAllowed,omitempty"`
	// ConnectDenied counts connect() calls denied by policy (or that would
	// have been denied, in audit mode).
	// +optional
	ConnectDenied int64 `json:"connectDenied,omitempty"`

	// DeviceAccessAllowed counts device-open calls permitted by policy.
	// +optional
	DeviceAccessAllowed int64 `json:"deviceAccessAllowed,omitempty"`
	// DeviceAccessDenied counts device-open calls denied by policy (or that
	// would have been denied, in audit mode).
	// +optional
	DeviceAccessDenied int64 `json:"deviceAccessDenied,omitempty"`
}

// ViolationRecord captures the most recent policy violation observed for this
// pod, kept lightweight (last one, not a full log) to bound CRD object size.
type ViolationRecord struct {
	// Hook identifies which hook produced the violation.
	// +kubebuilder:validation:Enum=execve;file_open;connect;device_open
	Hook string `json:"hook"`

	// Detail is a short human-readable description (e.g. the denied path or destination).
	// +optional
	Detail string `json:"detail,omitempty"`

	// ObservedAt is when the violation was observed by the agent.
	ObservedAt metav1.Time `json:"observedAt"`
}

// AgentIntegrityObserved carries the Janus-inspired agent integrity evidence:
// the eBPF agent DaemonSet's own image digest, as observed and verified by the
// Operator, plus optional runtime-measurement-register extension.
type AgentIntegrityObserved struct {
	// ImageDigest is the digest of the agent image actually running
	// (repo@sha256:<64 hex chars>) on the node hosting this pod.
	// +kubebuilder:validation:Pattern=`^.+@sha256:[a-f0-9]{64}$`
	ImageDigest string `json:"imageDigest"`

	// DigestVerified is true when the Operator confirmed ImageDigest matches
	// the RuntimeSecurityPolicy's AgentIntegrity.ExpectedImageDigest.
	DigestVerified bool `json:"digestVerified"`

	// RTMRExtended is true when the agent's measurement was successfully
	// extended into a platform runtime measurement register (e.g. TDX RTMR).
	// False (with RTMRIndex unset) documents the limitation when the platform
	// does not expose one, rather than silently assuming integrity.
	// +optional
	RTMRExtended bool `json:"rtmrExtended,omitempty"`

	// RTMRIndex identifies which register was extended, when RTMRExtended is true.
	// +optional
	RTMRIndex *int32 `json:"rtmrIndex,omitempty"`
}

// EvidenceSignature is the Ed25519 signature block over the canonical JSON
// encoding of this evidence's payload fields (spec + the status fields other
// than Signature itself), following the article 1 signing convention
// (github.com/imperium/ai-sovereign-finops-operator/pkg/crypto: CanonicalJSON
// + SHA-256, then Ed25519 over the canonical bytes, hex-encoded).
type EvidenceSignature struct {
	// Algorithm identifies the signature scheme.
	// +kubebuilder:validation:Enum=ed25519
	// +kubebuilder:default=ed25519
	Algorithm string `json:"algorithm"`

	// KeyIdentifier names the signing key used, for rotation/audit purposes.
	// +optional
	KeyIdentifier string `json:"keyIdentifier,omitempty"`

	// PayloadDigest is the SHA-256 hex digest of the canonical JSON payload that was signed.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	PayloadDigest string `json:"payloadDigest"`

	// Signature is the hex-encoded Ed25519 signature over the canonical payload.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{128}$`
	Signature string `json:"signature"`

	// IssuedAt is when this evidence was signed.
	IssuedAt metav1.Time `json:"issuedAt"`

	// ExpiresAt bounds the evidence's validity window.
	ExpiresAt metav1.Time `json:"expiresAt"`
}

// RuntimePlacementEvidenceSpec defines the desired state of RuntimePlacementEvidence.
// Desired state here is minimal: which policy/pod/node this recurring evidence
// object attests to. The interesting content is in Status, produced by the node agent.
type RuntimePlacementEvidenceSpec struct {
	// PolicyRef references the RuntimeSecurityPolicy this evidence attests conformance to.
	PolicyRef ObjectReference `json:"policyRef"`

	// TargetRef identifies the workload or pod this evidence describes.
	TargetRef ObjectReference `json:"targetRef"`

	// NodeName is the node the agent producing this evidence runs on.
	NodeName string `json:"nodeName"`
}

// RuntimePlacementEvidenceStatus defines the observed state of RuntimePlacementEvidence.
type RuntimePlacementEvidenceStatus struct {
	// ObservedGeneration is the last generation observed by the node agent.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// DecisionID is the immutable signed placement decision identity copied
	// from the RuntimeSecurityPolicy binding, tying this evidence back to D.
	// +optional
	DecisionID string `json:"decisionID,omitempty"`

	// DecisionHash is the SHA-256 canonical digest of the signed placement
	// decision payload D used to derive the referenced policy.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	// +optional
	DecisionHash string `json:"decisionHash,omitempty"`

	// PolicyHash is the SHA-256 canonical digest of the derived runtime policy
	// P that this evidence attests.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	// +optional
	PolicyHash string `json:"policyHash,omitempty"`

	// PolicyGeneration is the RuntimeSecurityPolicy generation applied by the
	// monitor when this evidence was emitted.
	// +optional
	PolicyGeneration int64 `json:"policyGeneration,omitempty"`

	// MonitorID identifies the monitor/agent key that signed this evidence.
	// It must match Signature.KeyIdentifier for independent verification.
	// +optional
	MonitorID string `json:"monitorID,omitempty"`

	// PodUID is the pod UID this evidence was actually collected against,
	// resolved via the Pod UID -> cgroup ID mapping.
	// +optional
	PodUID string `json:"podUID,omitempty"`

	// CgroupID is the cgroup v2 ID the agent resolved for this pod, encoded as
	// a decimal string (cgroup IDs are uint64 and may exceed safe JSON/YAML
	// integer precision).
	// +kubebuilder:validation:Pattern=`^[0-9]+$`
	// +optional
	CgroupID string `json:"cgroupID,omitempty"`

	// Conformance is the P5 (Runtime Conformance) verdict: whether observed
	// runtime behavior remained within the bounds of the referenced policy.
	// "incomplete" means observation itself cannot be trusted for this
	// evidence (events were dropped node-wide since the last emission, or
	// the monitor's own liveness could not be confirmed -- see
	// EventsDroppedSinceLastEvidence/LastHeartbeat) and MUST NOT be
	// silently reported as "conform" (Task 05/B1, Q3).
	// +kubebuilder:validation:Enum=conform;violation;unknown;incomplete
	// +optional
	Conformance string `json:"conformance,omitempty"`

	// DropCount is the cumulative count of eBPF ring-buffer submissions that
	// failed (buffer full) on this node since the agent process started, as
	// of this evidence emission. Node-wide, not per-pod: a dropped event's
	// cgroup is unknowable by construction (see agent.bpf.c emit_event).
	// +optional
	DropCount int64 `json:"dropCount,omitempty"`

	// EventsDroppedSinceLastEvidence is the delta of DropCount since this
	// policy's previous evidence emission. Nonzero forces Conformance to
	// "incomplete" for this emission (see Conformance's doc comment).
	// +optional
	EventsDroppedSinceLastEvidence int64 `json:"eventsDroppedSinceLastEvidence,omitempty"`

	// MonitorEpoch identifies the emitting agent process's lifetime (set
	// once, at agent startup). A change between two evidence objects for
	// the same pod reveals an agent restart -- a monitor-liveness signal a
	// verifier can check (Task 05/B3, Q5).
	// +optional
	MonitorEpoch string `json:"monitorEpoch,omitempty"`

	// LastHeartbeat is updated every evidence-emission cycle regardless of
	// whether this pod produced any new events, so a verifier can
	// distinguish "workload is quiet" (LastHeartbeat keeps advancing,
	// Behavior counters don't) from "monitor is dead/blind" (LastHeartbeat
	// stops advancing entirely).
	// +optional
	LastHeartbeat metav1.Time `json:"lastHeartbeat,omitempty"`

	// HookSetDigest is a deterministic hash of which eBPF hooks are
	// currently attached (depends on the node's enforcement mode). A change
	// between two evidence objects for the same MonitorEpoch reveals a hook
	// detachment/reattachment a verifier can check.
	// +optional
	HookSetDigest string `json:"hookSetDigest,omitempty"`

	// EvidenceMode reflects whether this evidence was produced under real
	// BPF-LSM enforcement, a simulated/audit-only fallback (e.g. this kernel's
	// BPF-LSM is compiled but not active), or is unverified.
	// +optional
	EvidenceMode EvidenceMode `json:"evidenceMode,omitempty"`

	// AgentIntegrity carries the Janus-inspired agent self-integrity evidence.
	AgentIntegrity AgentIntegrityObserved `json:"agentIntegrity"`

	// Behavior accumulates hook observation counters since the last emission.
	// +optional
	Behavior ObservedBehaviorCounters `json:"behavior,omitempty"`

	// EvidenceSequence is a per-policy monotonic emission counter maintained by
	// the node agent; gaps reveal missing evidence objects in the digest chain.
	// +kubebuilder:validation:Minimum=1
	// +optional
	EvidenceSequence int64 `json:"evidenceSequence,omitempty"`

	// LastViolation records the most recent policy violation, if any.
	// +optional
	LastViolation *ViolationRecord `json:"lastViolation,omitempty"`

	// BPFLockActive is true when the defense-in-depth BPF-lock hook is
	// currently blocking unauthorized BPF program loads on this node.
	// +optional
	BPFLockActive bool `json:"bpfLockActive,omitempty"`

	// PreviousEvidenceDigest links this evidence to the prior one for the same
	// pod, forming an append-only chain (mirrors the article 1 AIEvidenceRecord
	// PreviousRecordDigest convention) so tampering or gaps are detectable.
	// +kubebuilder:validation:Pattern=`^[a-f0-9]{64}$`
	// +optional
	PreviousEvidenceDigest string `json:"previousEvidenceDigest,omitempty"`

	// RevokedAt is set once a revocation was observed and access was retracted
	// for this pod, used to measure revocation propagation latency (Phase 6)
	// and to validate the "persistence after revocation" attack scenario (Phase 5).
	// Part of the SIGNED payload as of Task 06 (see AuthorizationState) --
	// unlike its pre-Task-06 history, this is now a trust-relevant claim a
	// verifier can check, not merely informational.
	// +optional
	RevokedAt *metav1.Time `json:"revokedAt,omitempty"`

	// AuthorizationState is the agent's own most recent, locally-observed
	// belief about whether the AIPlacementDecision/RuntimeSecurityPolicy
	// authorizing this pod is still present (authorized) or has disappeared
	// (revoked). Task 06/C4: this is deliberately separate from Conformance
	// -- Conformance answers "did observed behavior match policy P",
	// AuthorizationState answers "is the underlying decision D still
	// currently valid" -- a workload can be simultaneously conform (no
	// policy violations) and revoked (idle post-revocation, or still
	// running against a now-orphaned deny-by-default cgroup), and a
	// verifier must not conflate the two. Part of the signed payload.
	// +kubebuilder:validation:Enum=authorized;revoked;unknown
	// +optional
	AuthorizationState string `json:"authorizationState,omitempty"`

	// LastAuthorizationSync is updated every agent poll cycle (default 5s,
	// see --poll-interval) in which this pod's policy was confirmed still
	// present/live, and stops advancing the moment revocation is detected
	// (frozen at the last confirmed-authorized poll). Task 06/C5: this
	// bounds how stale an "authorized"/"conform" claim can be -- the agent
	// itself cannot know a revocation happened more recently than its own
	// last successful poll, so a verifier comparing (now -
	// LastAuthorizationSync) against its own tolerance gets an honest,
	// measured upper bound on staleness rather than an unconditional trust
	// assumption. Part of the signed payload.
	// +optional
	LastAuthorizationSync metav1.Time `json:"lastAuthorizationSync,omitempty"`

	// Signature is the Ed25519 signature over this evidence's payload.
	// +optional
	Signature EvidenceSignature `json:"signature,omitempty"`

	// Conditions captures evidence production/verification state.
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status
//+kubebuilder:resource:shortName=rpe
//+kubebuilder:printcolumn:name="Conformance",type=string,JSONPath=`.status.conformance`
//+kubebuilder:printcolumn:name="EvidenceMode",type=string,JSONPath=`.status.evidenceMode`
//+kubebuilder:printcolumn:name="Node",type=string,JSONPath=`.spec.nodeName`
//+kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RuntimePlacementEvidence is the Schema for the runtimeplacementevidences API
type RuntimePlacementEvidence struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RuntimePlacementEvidenceSpec   `json:"spec,omitempty"`
	Status RuntimePlacementEvidenceStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// RuntimePlacementEvidenceList contains a list of RuntimePlacementEvidence
type RuntimePlacementEvidenceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RuntimePlacementEvidence `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RuntimePlacementEvidence{}, &RuntimePlacementEvidenceList{})
}
