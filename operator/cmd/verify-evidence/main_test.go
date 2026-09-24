package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/evidence"
)

func TestVerifyEvidenceAcceptsValidObjectPair(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	report := verifyEvidence(ev, policy, pub, now.Add(30*time.Second), time.Minute, time.Minute)
	if !report.Valid {
		t.Fatalf("expected valid evidence, got %+v", report)
	}
	if report.FreshnessSeconds != 30 {
		t.Fatalf("expected freshness age 30s, got %d", report.FreshnessSeconds)
	}
}

func TestVerifyEvidenceRejectsTamperedDecisionBinding(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)
	ev.Status.DecisionHash = "tampered"

	report := verifyEvidence(ev, policy, pub, now.Add(30*time.Second), time.Minute, time.Minute)
	if report.Valid {
		t.Fatal("expected tampered decision hash to fail verification")
	}
}

func TestVerifyEvidenceRejectsIncompleteConformance(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	// Simulate what emitEvidence does when loss was detected this cycle,
	// then re-sign (a real agent would never sign "conform" together with a
	// nonzero drop delta -- see emitEvidence's override -- so re-signing
	// here models an evidence object the agent legitimately produced in
	// that state, not a tampered one).
	ev.Status.Conformance = "incomplete"
	ev.Status.EventsDroppedSinceLastEvidence = 3
	resignFixture(t, priv, ev)

	report := verifyEvidence(ev, policy, pub, now.Add(30*time.Second), time.Minute, time.Minute)
	if report.Valid {
		t.Fatal("expected incomplete conformance to fail verification")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "observation-completeness" {
			found = true
			if c.Passed {
				t.Fatalf("expected observation-completeness check to fail, got %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("expected an observation-completeness check to be reported")
	}
}

func TestVerifyEvidenceRejectsStaleHeartbeat(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	// Heartbeat frozen long before `now` -- models a dead/blind monitor
	// (Task 05 B3, Q5): the agent process stopped ticking, so nothing is
	// updating LastHeartbeat even though the last evidence it emitted still
	// says "conform".
	ev.Status.LastHeartbeat = metav1.NewTime(now.Add(-10 * time.Minute))
	resignFixture(t, priv, ev)

	report := verifyEvidence(ev, policy, pub, now.Add(30*time.Second), time.Minute, time.Minute)
	if report.Valid {
		t.Fatal("expected stale heartbeat to fail verification")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "monitor-heartbeat-fresh" {
			found = true
			if c.Passed {
				t.Fatalf("expected monitor-heartbeat-fresh check to fail, got %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("expected a monitor-heartbeat-fresh check to be reported")
	}
}

func TestVerifyEvidenceRejectsStaleAuthorizationSync(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	// LastAuthorizationSync frozen long before `now` -- models an agent
	// whose poll loop has stopped confirming the decision is still
	// present (e.g. agent stuck/dead), even though the last evidence it
	// emitted still says AuthorizationState=authorized. Task 06/C5: a
	// verifier must not treat this as a current "still authorized" claim.
	ev.Status.LastAuthorizationSync = metav1.NewTime(now.Add(-10 * time.Minute))
	resignFixture(t, priv, ev)

	report := verifyEvidence(ev, policy, pub, now.Add(30*time.Second), time.Minute, time.Minute)
	if report.Valid {
		t.Fatal("expected stale authorization sync to fail verification")
	}
	if report.AuthorizedAndCompliant {
		t.Fatal("expected AuthorizedAndCompliant=false when authorization currency cannot be confirmed")
	}
	found := false
	for _, c := range report.Checks {
		if c.Name == "authorization-currency" {
			found = true
			if c.Passed {
				t.Fatalf("expected authorization-currency check to fail, got %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("expected an authorization-currency check to be reported")
	}
}

func TestVerifyEvidence_AuthorizedAndCompliant_FalseWhenRevoked(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	// Task 06/C4: a revoked-but-quiescent pod (no denied attempts
	// observed, so Conformance stays "conform") must never be read as
	// "authorized and compliant" -- RuntimeCompliance and
	// AuthorizationValidity are separate claims. The evidence object
	// itself is still perfectly valid/trustworthy (correctly signed,
	// fresh, honestly reporting a revoked state) -- Valid can and should
	// stay true; only the derived AuthorizedAndCompliant answer changes.
	ev.Status.AuthorizationState = "revoked"
	revokedAt := metav1.NewTime(now)
	ev.Status.RevokedAt = &revokedAt
	resignFixture(t, priv, ev)

	report := verifyEvidence(ev, policy, pub, now.Add(30*time.Second), time.Minute, time.Minute)
	if !report.Valid {
		t.Fatalf("expected a correctly-signed, fresh, honestly-revoked evidence object to remain Valid, got %+v", report)
	}
	if report.AuthorizedAndCompliant {
		t.Fatal("expected AuthorizedAndCompliant=false for a revoked pod even though Conformance=conform")
	}
}

// resignFixture re-signs ev's current Status fields, for tests that mutate
// Status after signedFixture and need a self-consistent signature (as
// opposed to tamper-detection tests, which mutate post-signing on purpose).
func resignFixture(t *testing.T, priv ed25519.PrivateKey, ev *aiopsv1alpha1.RuntimePlacementEvidence) {
	t.Helper()
	payload := evidence.PayloadFromObject(ev)
	sig, err := evidence.Sign(priv, ev.Status.MonitorID, payload)
	if err != nil {
		t.Fatalf("re-sign evidence: %v", err)
	}
	ev.Status.Signature = aiopsv1alpha1.EvidenceSignature{
		Algorithm:     sig.Algorithm,
		KeyIdentifier: sig.KeyIdentifier,
		PayloadDigest: sig.PayloadDigest,
		Signature:     sig.SignatureHex,
		IssuedAt:      metav1.NewTime(sig.IssuedAt),
		ExpiresAt:     metav1.NewTime(sig.ExpiresAt),
	}
}

func TestVerifyEvidenceRejectsStaleEvidence(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	report := verifyEvidence(ev, policy, pub, now.Add(2*time.Minute), time.Minute, time.Minute)
	if report.Valid {
		t.Fatal("expected stale evidence to fail verification")
	}
}

func TestVerifyFilesReadsYAMLWithoutClusterState(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	policy, ev := signedFixture(t, priv, now)

	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	evidencePath := filepath.Join(dir, "evidence.yaml")
	writeYAML(t, policyPath, policy)
	writeYAML(t, evidencePath, ev)

	report, err := verifyFiles(evidencePath, policyPath, crypto.PubKeyToHex(pub), now.Add(30*time.Second), time.Minute, time.Minute)
	if err != nil {
		t.Fatalf("verify files: %v", err)
	}
	if !report.Valid {
		t.Fatalf("expected valid file verification, got %+v", report)
	}
}

func signedFixture(t *testing.T, priv ed25519.PrivateKey, now time.Time) (*aiopsv1alpha1.RuntimeSecurityPolicy, *aiopsv1alpha1.RuntimePlacementEvidence) {
	t.Helper()
	policy := &aiopsv1alpha1.RuntimeSecurityPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "guarded-policy", Namespace: "workloads", Generation: 7},
		Spec: aiopsv1alpha1.RuntimeSecurityPolicySpec{
			TargetRef:      aiopsv1alpha1.ObjectReference{Name: "guarded-pod", Namespace: "workloads"},
			Binding:        aiopsv1alpha1.PlacementBinding{DecisionID: "decision-1", PodUID: "pod-uid-1", NodeIdentity: "node-1"},
			AgentIntegrity: aiopsv1alpha1.AgentIntegritySpec{ExpectedImageDigest: "repo/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			Derivation:     aiopsv1alpha1.PolicyDerivationTrace{DecisionHash: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", PolicyHash: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"},
		},
	}
	ev := &aiopsv1alpha1.RuntimePlacementEvidence{
		ObjectMeta: metav1.ObjectMeta{Name: "guarded-policy", Namespace: "aiops-system"},
		Spec: aiopsv1alpha1.RuntimePlacementEvidenceSpec{
			PolicyRef: aiopsv1alpha1.ObjectReference{Name: policy.Name, Namespace: policy.Namespace},
			TargetRef: policy.Spec.TargetRef,
			NodeName:  "node-1",
		},
		Status: aiopsv1alpha1.RuntimePlacementEvidenceStatus{
			DecisionID:            "decision-1",
			DecisionHash:          "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			PolicyHash:            "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			PolicyGeneration:      7,
			MonitorID:             "agent-node-1",
			PodUID:                "pod-uid-1",
			CgroupID:              "123",
			Conformance:           "conform",
			EvidenceMode:          aiopsv1alpha1.EvidenceModeSimulated,
			EvidenceSequence:      1,
			AgentIntegrity:        aiopsv1alpha1.AgentIntegrityObserved{ImageDigest: policy.Spec.AgentIntegrity.ExpectedImageDigest, DigestVerified: true},
			Behavior:              aiopsv1alpha1.ObservedBehaviorCounters{ExecAllowed: 1},
			MonitorEpoch:          "epoch-1",
			LastHeartbeat:         metav1.NewTime(now),
			HookSetDigest:         "hookdigest-1",
			AuthorizationState:    "authorized",
			LastAuthorizationSync: metav1.NewTime(now),
		},
	}
	payload := evidence.Payload{
		SchemaVersion:             evidence.SchemaVersion,
		PolicyRefName:             policy.Name,
		PolicyRefNamespace:        policy.Namespace,
		TargetRefName:             policy.Spec.TargetRef.Name,
		TargetRefNamespace:        policy.Spec.TargetRef.Namespace,
		DecisionID:                ev.Status.DecisionID,
		DecisionHash:              ev.Status.DecisionHash,
		PolicyHash:                ev.Status.PolicyHash,
		PolicyGeneration:          ev.Status.PolicyGeneration,
		MonitorID:                 ev.Status.MonitorID,
		NodeName:                  ev.Spec.NodeName,
		PodUID:                    ev.Status.PodUID,
		CgroupID:                  ev.Status.CgroupID,
		Conformance:               ev.Status.Conformance,
		EvidenceMode:              string(ev.Status.EvidenceMode),
		AgentImageDigest:          ev.Status.AgentIntegrity.ImageDigest,
		AgentDigestVerified:       ev.Status.AgentIntegrity.DigestVerified,
		Behavior:                  evidence.BehaviorCounters{ExecAllowed: 1},
		EvidenceSequence:          ev.Status.EvidenceSequence,
		MonitorEpoch:              ev.Status.MonitorEpoch,
		LastHeartbeat:             ev.Status.LastHeartbeat.Time.UTC().Unix(),
		HookSetDigest:             ev.Status.HookSetDigest,
		AuthorizationState:        ev.Status.AuthorizationState,
		LastAuthorizationSyncUnix: ev.Status.LastAuthorizationSync.Time.UTC().Unix(),
		IssuedAt:                  now.Unix(),
		ExpiresAt:                 now.Add(10 * time.Minute).Unix(),
	}
	sig, err := evidence.Sign(priv, ev.Status.MonitorID, payload)
	if err != nil {
		t.Fatalf("sign evidence: %v", err)
	}
	ev.Status.Signature = aiopsv1alpha1.EvidenceSignature{
		Algorithm:     sig.Algorithm,
		KeyIdentifier: sig.KeyIdentifier,
		PayloadDigest: sig.PayloadDigest,
		Signature:     sig.SignatureHex,
		IssuedAt:      metav1.NewTime(sig.IssuedAt),
		ExpiresAt:     metav1.NewTime(sig.ExpiresAt),
	}
	return policy, ev
}

func writeYAML(t *testing.T, path string, obj any) {
	t.Helper()
	raw, err := yaml.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal yaml: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
}
