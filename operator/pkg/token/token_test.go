package token

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
)

func TestOptionalPolicyRequestsAreAbsentFromLegacyPayloadJSON(t *testing.T) {
	data, err := json.Marshal(validPayload())
	if err != nil {
		t.Fatalf("marshal legacy payload: %v", err)
	}
	for _, field := range [][]byte{[]byte(`"exec_policy_request"`), []byte(`"file_policy_request"`)} {
		if bytes.Contains(data, field) {
			t.Fatalf("optional field %s changed legacy payload bytes: %s", field, data)
		}
	}
}

// mint is a test-only helper that mints a token the way article 1's
// scheduler does (see pkg/token.Mint there), so these tests exercise this
// package's Verify/VerifyForPod/Decode against a realistic artifact. Article
// 2 itself never mints tokens — only verifies them.
func mint(t *testing.T, priv ed25519.PrivateKey, payload Payload) Token {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return Token{Payload: payload, Signature: platformcrypto.Ed25519Sign(priv, data)}
}

func validPayload() Payload {
	now := time.Now().UTC()
	return Payload{
		DecisionID:      "workloads/risk-assistant",
		DecisionVersion: 1,
		DecisionEpoch:   1,
		DecisionNonce:   "nonce-1",
		PodUID:          "43f0b3ff-ddc8-4ce1-b069-c56b7335b901",
		PodSpecHash:     "f3154cc3ca7f436173b76cdbe58d10e45b6111b4490ea7db3f7f792434c6ca0b",
		ImageDigest:     "registry.example.com/vllm@sha256:aaaa",
		ModelDigest:     "sha256:model-e2e",
		NodeIdentity:    "ai-platform-control-plane",
		RuntimeClass:    "kata-qemu-snp",
		EvidenceHash:    "1fbb2c68d9312788ba8137e07cc519acaf8158fd96aab23e3f6a4517e196018",
		PolicyHash:      "2d1aba3b79e0cab0b060b30b9ef4501936c70cb0385f7aca051b7e3952be6a2",
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(5 * time.Minute).Unix(),
	}
}

func TestVerifyAcceptsValidToken(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	tok := mint(t, priv, validPayload())

	if err := Verify(pub, tok); err != nil {
		t.Fatalf("expected valid token to verify, got: %v", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := validPayload()
	payload.IssuedAt = time.Now().Add(-time.Hour).Unix()
	payload.ExpiresAt = time.Now().Add(-time.Minute).Unix()
	tok := mint(t, priv, payload)

	err = Verify(pub, tok)
	if err == nil {
		t.Fatal("expected expired token to fail verification")
	}
}

func TestVerifyRejectsMissingAntiReplayClaims(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := validPayload()
	payload.DecisionID = ""
	tok := mint(t, priv, payload)

	if err := Verify(pub, tok); err == nil {
		t.Fatal("expected missing decision_id to fail verification")
	}

	payload = validPayload()
	payload.DecisionVersion = 0
	tok = mint(t, priv, payload)
	if err := Verify(pub, tok); err == nil {
		t.Fatal("expected invalid decision_version to fail verification")
	}

	payload = validPayload()
	payload.DecisionEpoch = 0
	tok = mint(t, priv, payload)
	if err := Verify(pub, tok); err == nil {
		t.Fatal("expected invalid decision_epoch to fail verification")
	}

	payload = validPayload()
	payload.DecisionNonce = ""
	tok = mint(t, priv, payload)
	if err := Verify(pub, tok); err == nil {
		t.Fatal("expected missing decision_nonce to fail verification")
	}
}

func TestVerifyRejectsWrongSchedulerKey(t *testing.T) {
	_, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	otherPub, _, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate other key pair: %v", err)
	}
	tok := mint(t, priv, validPayload())

	if err := Verify(otherPub, tok); err == nil {
		t.Fatal("expected token signed by a different key to fail verification")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	tok := mint(t, priv, validPayload())
	tok.Payload.NodeIdentity = "attacker-controlled-node"

	if err := Verify(pub, tok); err == nil {
		t.Fatal("expected tampered payload to fail verification")
	}
}

func TestVerifyForPodDetectsDrift(t *testing.T) {
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	payload := validPayload()
	tok := mint(t, priv, payload)

	if err := VerifyForPod(pub, tok, payload.PodUID, payload.PodSpecHash, payload.NodeIdentity, payload.EvidenceHash, payload.PolicyHash); err != nil {
		t.Fatalf("expected matching context to verify, got: %v", err)
	}

	if err := VerifyForPod(pub, tok, "some-other-pod-uid", "", "", "", ""); err == nil {
		t.Fatal("expected pod UID mismatch to be detected")
	}
	if err := VerifyForPod(pub, tok, payload.PodUID, "different-spec-hash", "", "", ""); err == nil {
		t.Fatal("expected pod spec hash mismatch to be detected")
	}
	if err := VerifyForPod(pub, tok, payload.PodUID, "", "different-node", "", ""); err == nil {
		t.Fatal("expected node identity mismatch to be detected")
	}
}

func TestDecodeRealWorldAnnotationSample(t *testing.T) {
	// This is the literal annotation value captured in article 1's
	// article1/results/raw/kind/e2e-placement-decision.yaml (see
	// EXPERIMENTS_LOG.md Phase 1), used here only to confirm this package's
	// struct/JSON tags decode a real article-1 artifact without error. The
	// embedded signature will not verify (we do not have that run's private
	// key), only Decode()'s shape is under test.
	raw := `{"payload":{"pod_uid":"43f0b3ff-ddc8-4ce1-b069-c56b7335b901","pod_spec_hash":"f3154cc3ca7f436173b76cdbe58d10e45b6111b4490ea7db3f7f792434c6ca0b","image_digest":"registry.k8s.io/pause:3.9","model_digest":"sha256:model-e2e","node_identity":"ai-platform-control-plane","runtime_class":"simulated-kata-qemu-snp","evidence_hash":"1fbb2c68d9312788ba8137e07cc519acaf8158fd96aab23e3f6a4517e1960185","policy_hash":"2d1aba3b79e0cab0b060b30b9ef4501936c70cb0385f7aca051b7e3952be6a22","issued_at":1783233207,"expires_at":1783233507},"signature":"db56fdae30e2fa65cf8e3755928ddfa5c6240e961b877b3e336fc5db2d5e2fb2a506d5b6af955f435c34122b7b797aa1267a1f59459ba5b9d2433b179faf3e07"}`

	tok, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode real-world sample: %v", err)
	}
	if tok.Payload.PodUID != "43f0b3ff-ddc8-4ce1-b069-c56b7335b901" {
		t.Fatalf("unexpected pod UID: %s", tok.Payload.PodUID)
	}
	if tok.Payload.NodeIdentity != "ai-platform-control-plane" {
		t.Fatalf("unexpected node identity: %s", tok.Payload.NodeIdentity)
	}
	if tok.Signature == "" {
		t.Fatal("expected non-empty signature")
	}
}
