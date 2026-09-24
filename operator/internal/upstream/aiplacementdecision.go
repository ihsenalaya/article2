// Package upstream mirrors just the subset of article 1's
// AIPlacementDecision object (github.com/imperium/ai-sovereign-finops-operator,
// group aiops.imperium.io/v1alpha1) that the Runtime Guard Operator needs to
// read. It deliberately does not import that repo's Go module: the two
// articles are separate codebases/deliverables, and this operator only ever
// reads AIPlacementDecision objects (never reconciles or owns that CRD), so a
// narrow local mirror kept in sync with the documented contract
// (EXPERIMENTS_LOG.md, Phase 1) is preferable to a hard cross-repo dependency
// on ~30 unrelated CRD types article 1 also defines.
//
// Because this type is not owned here, it is intentionally excluded from this
// module's controller-gen CRD/object generation (no +kubebuilder:object:root
// marker) — DeepCopyObject is implemented by hand below. Applying
// config/crd/bases/*.yaml from this repo must never install a
// aiplacementdecisions.aiops.imperium.io CRD; that CRD is owned and installed
// by article 1's chart.
package upstream

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// GroupVersion matches article 1's aiops.imperium.io/v1alpha1 API group.
var GroupVersion = schema.GroupVersion{Group: "aiops.imperium.io", Version: "v1alpha1"}

// SchemeBuilder registers AIPlacementDecision (read-only mirror) into a scheme.
var SchemeBuilder = runtime.NewSchemeBuilder(addKnownTypes)

// AddToScheme registers the AIPlacementDecision mirror type.
var AddToScheme = SchemeBuilder.AddToScheme

func addKnownTypes(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&AIPlacementDecision{},
		&AIPlacementDecisionList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}

// ObjectRef mirrors article 1's ObjectReference{name, namespace?} convention.
type ObjectRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// PlacementTokenSpec mirrors article 1's PlacementTokenSpec.
type PlacementTokenSpec struct {
	Required   bool  `json:"required,omitempty"`
	TTLSeconds int32 `json:"ttlSeconds,omitempty"`
}

// AIPlacementDecisionSpec mirrors the fields of article 1's
// AIPlacementDecisionSpec that this Operator reads.
type AIPlacementDecisionSpec struct {
	TargetRef      ObjectRef          `json:"targetRef"`
	PolicyRef      ObjectRef          `json:"policyRef"`
	EvidenceRef    *ObjectRef         `json:"evidenceRef,omitempty"`
	PlacementToken PlacementTokenSpec `json:"placementToken,omitempty"`
	SchedulerName  string             `json:"schedulerName,omitempty"`
}

// AIPlacementDecisionStatus mirrors the fields of article 1's
// AIPlacementDecisionStatus that this Operator reads.
type AIPlacementDecisionStatus struct {
	ObservedGeneration   int64              `json:"observedGeneration,omitempty"`
	Decision             string             `json:"decision,omitempty"`
	NodeName             string             `json:"nodeName,omitempty"`
	PlacementTokenDigest string             `json:"placementTokenDigest,omitempty"`
	Simulated            bool               `json:"simulated,omitempty"`
	Conditions           []metav1.Condition `json:"conditions,omitempty"`
}

// AIPlacementDecision is a read-only mirror of article 1's CRD instance.
// The signed placement token itself is not a status field on this object —
// article 1's scheduler carries it as JSON in the
// "ai.sovereign.io/placement-token" annotation (see pkg/token.AnnotationKey).
type AIPlacementDecision struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AIPlacementDecisionSpec   `json:"spec,omitempty"`
	Status AIPlacementDecisionStatus `json:"status,omitempty"`
}

// AIPlacementDecisionList is a list of AIPlacementDecision.
type AIPlacementDecisionList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AIPlacementDecision `json:"items"`
}

// DeepCopyObject implements runtime.Object.
func (in *AIPlacementDecision) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AIPlacementDecision)
	in.DeepCopyInto(out)
	return out
}

// DeepCopyInto copies all fields of AIPlacementDecision into out.
func (in *AIPlacementDecision) DeepCopyInto(out *AIPlacementDecision) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	if in.Spec.EvidenceRef != nil {
		ref := *in.Spec.EvidenceRef
		out.Spec.EvidenceRef = &ref
	}
	if in.Status.Conditions != nil {
		out.Status.Conditions = make([]metav1.Condition, len(in.Status.Conditions))
		copy(out.Status.Conditions, in.Status.Conditions)
	}
}

// DeepCopyObject implements runtime.Object.
func (in *AIPlacementDecisionList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(AIPlacementDecisionList)
	out.TypeMeta = in.TypeMeta
	out.ListMeta = in.ListMeta
	if in.Items != nil {
		out.Items = make([]AIPlacementDecision, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
	return out
}
