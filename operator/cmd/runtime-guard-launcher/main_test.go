package main

import (
	"os"
	"path/filepath"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
)

func TestIsCurrentEnforcementReadyRejectsStaleGeneration(t *testing.T) {
	now := metav1.Now()
	policy := &aiopsv1alpha1.RuntimeSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Generation: 3},
		Status: aiopsv1alpha1.RuntimeSecurityPolicyStatus{
			EnforcementReadyAt:      &now,
			AppliedPolicyGeneration: 2,
			Conditions: []metav1.Condition{{
				Type:               enforcementReadyConditionType,
				Status:             metav1.ConditionTrue,
				ObservedGeneration: 2,
			}},
		},
	}
	if isCurrentEnforcementReady(policy) {
		t.Fatal("expected stale applied generation to be rejected")
	}

	policy.Status.AppliedPolicyGeneration = 3
	policy.Status.Conditions[0].ObservedGeneration = 3
	if !isCurrentEnforcementReady(policy) {
		t.Fatal("expected current applied generation to be accepted")
	}
}

func TestProbeReadyUsesReadyFile(t *testing.T) {
	readyFile := filepath.Join(t.TempDir(), "ready")

	if code := probeReadyFile(readyFile); code == 0 {
		t.Fatal("expected probe to fail before ready file exists")
	}

	if err := os.WriteFile(readyFile, []byte("ready\n"), 0o644); err != nil {
		t.Fatalf("write ready file: %v", err)
	}
	if code := probeReadyFile(readyFile); code != 0 {
		t.Fatalf("expected probe to pass after ready file exists, got exit code %d", code)
	}
}
