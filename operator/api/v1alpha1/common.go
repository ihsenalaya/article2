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

// ObjectReference identifies another object in the same or a different namespace.
// Mirrors the convention used by the article 1 operator
// (github.com/imperium/ai-sovereign-finops-operator) so both CRD families stay
// consistent for a reader of the thesis.
type ObjectReference struct {
	// Name of the referenced object.
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`

	// Namespace of the referenced object. Defaults to the owner namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// EvidenceMode mirrors the article 1 AttestationEvidence convention: "real" only
// after genuine enforcement/attestation, "simulated" in kind/dev (audit-only
// BPF-LSM fallback), "unverified" when verification could not run at all.
// +kubebuilder:validation:Enum=real;simulated;unverified
type EvidenceMode string

const (
	EvidenceModeReal       EvidenceMode = "real"
	EvidenceModeSimulated  EvidenceMode = "simulated"
	EvidenceModeUnverified EvidenceMode = "unverified"
)

// VerificationStatus mirrors the article 1 AttestationEvidence convention.
// +kubebuilder:validation:Enum=Verified;Failed;Unavailable
type VerificationStatus string

const (
	VerificationStatusVerified    VerificationStatus = "Verified"
	VerificationStatusFailed      VerificationStatus = "Failed"
	VerificationStatusUnavailable VerificationStatus = "Unavailable"
)
