package main

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/lsmdetect"
	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
)

func TestMarkPolicyEnforcementReady(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register policy scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register core scheme: %v", err)
	}

	policy := &aiopsv1alpha1.RuntimeSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "guarded", Namespace: "workloads", Generation: 7},
	}
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "guarded", Namespace: "workloads"}}
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, pod).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()

	if err := markPolicyEnforcementReady(context.Background(), kubeClient, policy, pod, "node-a", []uint64{101, 202}, lsmdetect.ModeAudit); err != nil {
		t.Fatalf("mark readiness: %v", err)
	}

	var gotPolicy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: "guarded", Namespace: "workloads"}, &gotPolicy); err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if gotPolicy.Status.EnforcementReadyAt == nil {
		t.Fatal("expected enforcementReadyAt")
	}
	if gotPolicy.Status.AppliedPolicyGeneration != 7 {
		t.Fatalf("expected applied generation 7, got %d", gotPolicy.Status.AppliedPolicyGeneration)
	}
	if gotPolicy.Status.AppliedNodeName != "node-a" {
		t.Fatalf("expected node-a, got %q", gotPolicy.Status.AppliedNodeName)
	}
	if len(gotPolicy.Status.AppliedCgroupIDs) != 2 || gotPolicy.Status.AppliedCgroupIDs[0] != "101" || gotPolicy.Status.AppliedCgroupIDs[1] != "202" {
		t.Fatalf("unexpected cgroups: %+v", gotPolicy.Status.AppliedCgroupIDs)
	}
	condition := meta.FindStatusCondition(gotPolicy.Status.Conditions, enforcementReadyConditionType)
	if condition == nil || condition.Status != metav1.ConditionTrue || condition.ObservedGeneration != 7 {
		t.Fatalf("unexpected readiness condition: %+v", condition)
	}

	var gotPod corev1.Pod
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: "guarded", Namespace: "workloads"}, &gotPod); err != nil {
		t.Fatalf("get pod: %v", err)
	}
	if gotPod.Annotations[enforcementPolicyAnnotation] != "workloads/guarded" || gotPod.Annotations[enforcementReadyAnnotation] == "" {
		t.Fatalf("expected pod readiness annotations, got %+v", gotPod.Annotations)
	}

	if gotPolicy.Status.EnforcementReadyMonotonicNs == nil {
		t.Fatal("expected enforcementReadyMonotonicNs to be set")
	}
	firstMonotonicNs := *gotPolicy.Status.EnforcementReadyMonotonicNs

	firstReadyAt := gotPolicy.Status.EnforcementReadyAt.DeepCopy()
	if err := markPolicyEnforcementReady(context.Background(), kubeClient, &gotPolicy, &gotPod, "node-a", []uint64{101, 202}, lsmdetect.ModeAudit); err != nil {
		t.Fatalf("mark readiness again: %v", err)
	}
	var afterSecondMark aiopsv1alpha1.RuntimeSecurityPolicy
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: "guarded", Namespace: "workloads"}, &afterSecondMark); err != nil {
		t.Fatalf("get policy after second mark: %v", err)
	}
	if !afterSecondMark.Status.EnforcementReadyAt.Equal(firstReadyAt) {
		t.Fatalf("expected enforcementReadyAt to remain stable for same generation, got first=%s second=%s", firstReadyAt, afterSecondMark.Status.EnforcementReadyAt)
	}
	if afterSecondMark.Status.EnforcementReadyMonotonicNs == nil || *afterSecondMark.Status.EnforcementReadyMonotonicNs != firstMonotonicNs {
		t.Fatalf("expected enforcementReadyMonotonicNs to remain stable for same generation, got first=%d second=%v",
			firstMonotonicNs, afterSecondMark.Status.EnforcementReadyMonotonicNs)
	}
}

func TestMarkPolicyEnforcementReady_NewGenerationResetsFirstObservedOperation(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register policy scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register core scheme: %v", err)
	}

	priorObservedNs := int64(123456789)
	policy := &aiopsv1alpha1.RuntimeSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "guarded", Namespace: "workloads", Generation: 1},
		Status: aiopsv1alpha1.RuntimeSecurityPolicyStatus{
			// Simulates a policy that already has a t_c recorded from a
			// PRIOR generation's enforcement-ready cycle.
			AppliedPolicyGeneration:           1,
			EnforcementReadyAt:                &metav1.Time{},
			FirstObservedOperationMonotonicNs: &priorObservedNs,
			Conditions: []metav1.Condition{{
				Type:               enforcementReadyConditionType,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 1,
			}},
		},
	}
	policy.Generation = 2 // a new generation has since been produced
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "guarded", Namespace: "workloads"}}
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy, pod).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()

	if err := markPolicyEnforcementReady(context.Background(), kubeClient, policy, pod, "node-a", []uint64{101}, lsmdetect.ModeAudit); err != nil {
		t.Fatalf("mark readiness: %v", err)
	}

	var got aiopsv1alpha1.RuntimeSecurityPolicy
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: "guarded", Namespace: "workloads"}, &got); err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if got.Status.FirstObservedOperationMonotonicNs != nil {
		t.Fatalf("expected FirstObservedOperationMonotonicNs to be cleared on a new generation, got %v",
			*got.Status.FirstObservedOperationMonotonicNs)
	}
	if got.Status.AppliedPolicyGeneration != 2 {
		t.Fatalf("expected applied generation 2, got %d", got.Status.AppliedPolicyGeneration)
	}
}
