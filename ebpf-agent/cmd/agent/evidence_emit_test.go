package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/evidence"
)

func TestEmitEvidenceBindsDecisionPolicyMonitorAndFreshness(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register scheme: %v", err)
	}
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&aiopsv1alpha1.RuntimePlacementEvidence{}).
		Build()
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	info := trackedPod{
		podUID:             "pod-uid-1",
		targetRef:          types.NamespacedName{Name: "guarded-pod", Namespace: "workloads"},
		cgroupIDs:          []uint64{123},
		decisionID:         "decision-1",
		decisionHash:       "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		policyHash:         "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		policyGeneration:   7,
		evidenceSequence:   2,
		lastEvidenceDigest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	heartbeat := time.Now().UTC()
	digest, sequence, ok := emitEvidence(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		kubeClient,
		types.NamespacedName{Name: "guarded-policy", Namespace: "workloads"},
		info,
		newAccumulator(),
		priv,
		"repo/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"node-1",
		"aiops-system",
		aiopsv1alpha1.EvidenceModeSimulated,
		"epoch-1",
		"hookdigest-1",
		heartbeat,
		42, // cumulativeDropCount
		0,  // eventsDroppedSinceLastEvidence
	)
	if !ok {
		t.Fatal("expected evidence emission to succeed")
	}
	if sequence != 3 {
		t.Fatalf("expected sequence 3, got %d", sequence)
	}

	var got aiopsv1alpha1.RuntimePlacementEvidence
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: "guarded-policy", Namespace: "aiops-system"}, &got); err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	if got.Spec.TargetRef.Name != "guarded-pod" || got.Spec.TargetRef.Namespace != "workloads" {
		t.Fatalf("expected targetRef to point at real pod, got %+v", got.Spec.TargetRef)
	}
	if got.Status.DecisionID != info.decisionID || got.Status.DecisionHash != info.decisionHash || got.Status.PolicyHash != info.policyHash {
		t.Fatalf("missing D/P binding in evidence status: %+v", got.Status)
	}
	if got.Status.PolicyGeneration != 7 || got.Status.MonitorID != "agent-node-1" || got.Status.EvidenceSequence != 3 {
		t.Fatalf("missing monitor/freshness fields in evidence status: %+v", got.Status)
	}
	if got.Status.PreviousEvidenceDigest != info.lastEvidenceDigest {
		t.Fatalf("expected previous digest %q, got %q", info.lastEvidenceDigest, got.Status.PreviousEvidenceDigest)
	}
	if got.Status.Signature.PayloadDigest != digest {
		t.Fatalf("returned digest %q does not match object digest %q", digest, got.Status.Signature.PayloadDigest)
	}
	if got.Status.Signature.IssuedAt.IsZero() || got.Status.Signature.ExpiresAt.Before(&metav1.Time{Time: time.Now().UTC()}) {
		t.Fatalf("expected non-expired signature timestamps, got %+v", got.Status.Signature)
	}
	if err := evidence.Verify(pub, evidence.PayloadFromObject(&got), evidence.SignatureFromObject(&got)); err != nil {
		t.Fatalf("expected emitted evidence signature to verify: %v", err)
	}
	if got.Status.Conformance != "conform" {
		t.Fatalf("expected conform with no drops/violations, got %q", got.Status.Conformance)
	}
	if got.Status.DropCount != 42 {
		t.Fatalf("expected dropCount 42, got %d", got.Status.DropCount)
	}
	if got.Status.MonitorEpoch != "epoch-1" || got.Status.HookSetDigest != "hookdigest-1" {
		t.Fatalf("expected monitor identity fields to be set, got %+v", got.Status)
	}
	// metav1.Time is second-resolution (RFC3339, no fractional seconds) --
	// fine for a heartbeat on a multi-second evidence-interval cadence, so
	// compare at that resolution rather than requiring exact equality.
	if !got.Status.LastHeartbeat.Time.Truncate(time.Second).Equal(heartbeat.Truncate(time.Second)) {
		t.Fatalf("expected lastHeartbeat %v, got %v", heartbeat, got.Status.LastHeartbeat.Time)
	}
}

func TestEmitEvidence_EventLossForcesIncompleteConformance(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register scheme: %v", err)
	}
	kubeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithStatusSubresource(&aiopsv1alpha1.RuntimePlacementEvidence{}).
		Build()
	_, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	info := trackedPod{
		podUID:    "pod-uid-2",
		targetRef: types.NamespacedName{Name: "guarded-pod", Namespace: "workloads"},
		cgroupIDs: []uint64{456},
	}
	// Even with zero denied operations observed (which alone would mean
	// "conform"), a nonzero eventsDroppedSinceLastEvidence must force
	// "incomplete" -- Task 05 B1's central property (Q3): a dropped
	// violation is indistinguishable from a dropped benign event, so
	// "conform" must never be reported while loss is known to have occurred.
	_, _, ok := emitEvidence(
		context.Background(),
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		kubeClient,
		types.NamespacedName{Name: "lossy-policy", Namespace: "workloads"},
		info,
		newAccumulator(),
		priv,
		"repo/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"node-1",
		"aiops-system",
		aiopsv1alpha1.EvidenceModeSimulated,
		"epoch-1",
		"hookdigest-1",
		time.Now().UTC(),
		100, // cumulativeDropCount
		5,   // eventsDroppedSinceLastEvidence -- loss occurred this cycle
	)
	if !ok {
		t.Fatal("expected evidence emission to succeed")
	}

	var got aiopsv1alpha1.RuntimePlacementEvidence
	if err := kubeClient.Get(context.Background(), types.NamespacedName{Name: "lossy-policy", Namespace: "aiops-system"}, &got); err != nil {
		t.Fatalf("get evidence: %v", err)
	}
	if got.Status.Conformance != "incomplete" {
		t.Fatalf("expected conformance=incomplete when events were dropped, got %q", got.Status.Conformance)
	}
	if got.Status.EventsDroppedSinceLastEvidence != 5 {
		t.Fatalf("expected eventsDroppedSinceLastEvidence=5, got %d", got.Status.EventsDroppedSinceLastEvidence)
	}
}
