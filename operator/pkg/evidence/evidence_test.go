package evidence

import (
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
)

func testPayload() Payload {
	now := time.Now().UTC()
	return Payload{
		SchemaVersion:                  SchemaVersion,
		PolicyRefName:                  "risk-assistant-policy",
		PolicyRefNamespace:             "workloads",
		TargetRefName:                  "risk-assistant",
		TargetRefNamespace:             "workloads",
		DecisionID:                     "decision-1",
		DecisionHash:                   "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		PolicyHash:                     "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		PolicyGeneration:               7,
		MonitorID:                      "agent-node-1",
		NodeName:                       "node-1",
		PodUID:                         "pod-uid-1",
		CgroupID:                       "123456",
		Conformance:                    "conform",
		EvidenceMode:                   "simulated",
		AgentImageDigest:               "repo/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		AgentDigestVerified:            true,
		Behavior:                       BehaviorCounters{ExecAllowed: 3, ConnectDenied: 1},
		EvidenceSequence:               4,
		PreviousDigest:                 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		DropCount:                      0,
		EventsDroppedSinceLastEvidence: 0,
		MonitorEpoch:                   "epoch-1",
		LastHeartbeat:                  now.Unix(),
		HookSetDigest:                  "hookdigest-1",
		RevokedAtUnix:                  0,
		AuthorizationState:             "authorized",
		LastAuthorizationSyncUnix:      now.Unix(),
		IssuedAt:                       now.Unix(),
		ExpiresAt:                      now.Add(5 * time.Minute).Unix(),
	}
}

func TestSignVerify_RoundTrip(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := testPayload()

	sig, err := Sign(priv, "test-key-1", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if sig.Algorithm != "ed25519" {
		t.Errorf("expected algorithm ed25519, got %s", sig.Algorithm)
	}
	if err := Verify(pub, payload, sig); err != nil {
		t.Fatalf("expected valid signature to verify, got: %v", err)
	}
}

func TestVerify_RejectsTamperedPayload(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := testPayload()
	sig, err := Sign(priv, "test-key-1", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := payload
	tampered.Conformance = "violation"
	if err := Verify(pub, tampered, sig); err == nil {
		t.Fatal("expected tampered payload to fail verification")
	}
}

func TestVerify_RejectsWrongKey(t *testing.T) {
	_, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	otherPub, _, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate other key pair: %v", err)
	}
	payload := testPayload()
	sig, err := Sign(priv, "test-key-1", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := Verify(otherPub, payload, sig); err == nil {
		t.Fatal("expected signature signed by a different key to fail verification")
	}
}

func TestSign_RejectsNilKey(t *testing.T) {
	if _, err := Sign(nil, "k", testPayload()); err == nil {
		t.Fatal("expected error for nil private key")
	}
}

func TestSignVerify_BehaviorCountersAreCovered(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := testPayload()
	sig, err := Sign(priv, "test-key-1", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	tampered := payload
	tampered.Behavior.ConnectDenied = 0
	if err := Verify(pub, tampered, sig); err == nil {
		t.Fatal("expected tampered behavior counters to fail verification")
	}
}

func TestSignVerify_DecisionPolicyAndFreshnessFieldsAreCovered(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := testPayload()
	sig, err := Sign(priv, "test-key-1", payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	cases := map[string]func(*Payload){
		"decision id": func(p *Payload) { p.DecisionID = "decision-2" },
		"decision hash": func(p *Payload) {
			p.DecisionHash = "different-decision-hash"
		},
		"policy hash": func(p *Payload) { p.PolicyHash = "different-policy-hash" },
		"monitor id":  func(p *Payload) { p.MonitorID = "agent-other-node" },
		"sequence":    func(p *Payload) { p.EvidenceSequence++ },
		"previous":    func(p *Payload) { p.PreviousDigest = "" },
		"issued_at":   func(p *Payload) { p.IssuedAt++ },
		"expires_at":  func(p *Payload) { p.ExpiresAt++ },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tampered := payload
			mutate(&tampered)
			if err := Verify(pub, tampered, sig); err == nil {
				t.Fatal("expected tampered payload to fail verification")
			}
		})
	}
}

func TestPayloadFromObjectReconstructsSignedPayload(t *testing.T) {
	payload := testPayload()
	obj := &aiopsv1alpha1.RuntimePlacementEvidence{
		Spec: aiopsv1alpha1.RuntimePlacementEvidenceSpec{
			PolicyRef: aiopsv1alpha1.ObjectReference{Name: payload.PolicyRefName, Namespace: payload.PolicyRefNamespace},
			TargetRef: aiopsv1alpha1.ObjectReference{Name: payload.TargetRefName, Namespace: payload.TargetRefNamespace},
			NodeName:  payload.NodeName,
		},
		Status: aiopsv1alpha1.RuntimePlacementEvidenceStatus{
			DecisionID:                     payload.DecisionID,
			DecisionHash:                   payload.DecisionHash,
			PolicyHash:                     payload.PolicyHash,
			PolicyGeneration:               payload.PolicyGeneration,
			MonitorID:                      payload.MonitorID,
			PodUID:                         payload.PodUID,
			CgroupID:                       payload.CgroupID,
			Conformance:                    payload.Conformance,
			EvidenceMode:                   aiopsv1alpha1.EvidenceMode(payload.EvidenceMode),
			PreviousEvidenceDigest:         payload.PreviousDigest,
			EvidenceSequence:               payload.EvidenceSequence,
			AgentIntegrity:                 aiopsv1alpha1.AgentIntegrityObserved{ImageDigest: payload.AgentImageDigest, DigestVerified: payload.AgentDigestVerified},
			Behavior:                       aiopsv1alpha1.ObservedBehaviorCounters{ExecAllowed: 3, ConnectDenied: 1},
			DropCount:                      payload.DropCount,
			EventsDroppedSinceLastEvidence: payload.EventsDroppedSinceLastEvidence,
			MonitorEpoch:                   payload.MonitorEpoch,
			LastHeartbeat:                  metav1.NewTime(time.Unix(payload.LastHeartbeat, 0)),
			HookSetDigest:                  payload.HookSetDigest,
			AuthorizationState:             payload.AuthorizationState,
			LastAuthorizationSync:          metav1.NewTime(time.Unix(payload.LastAuthorizationSyncUnix, 0)),
			Signature:                      aiopsv1alpha1.EvidenceSignature{IssuedAt: metav1.NewTime(time.Unix(payload.IssuedAt, 0)), ExpiresAt: metav1.NewTime(time.Unix(payload.ExpiresAt, 0))},
		},
	}

	got := PayloadFromObject(obj)
	if got != payload {
		t.Fatalf("reconstructed payload mismatch:\n got: %+v\nwant: %+v", got, payload)
	}
}
