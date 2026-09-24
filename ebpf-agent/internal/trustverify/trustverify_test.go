package trustverify

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

// TestHashComparisonCatchesTampering is the core security property Task
// 11 adds: hash(P_received) must differ from hash(derive(D)) when P's
// actual rule content has been changed after the operator derived it
// from D, even though nothing about D itself changed. This is deliberately
// tested directly (not only via the full Verify() integration path, which
// needs a fake client and a signed token) so this specific property has
// its own fast, isolated regression coverage.
func TestHashComparisonCatchesTampering(t *testing.T) {
	decRef := aiopsv1alpha1.ObjectReference{Name: "d1", Namespace: "workloads"}
	targetRef := aiopsv1alpha1.ObjectReference{Name: "pod1", Namespace: "workloads"}
	binding := aiopsv1alpha1.PlacementBinding{DecisionID: "workloads/d1", DecisionVersion: 1, DecisionEpoch: 1}
	digest := "repo@sha256:" + "0000000000000000000000000000000000000000000000000000000000000000"[:64]

	expected := expectedFromDecision(decRef, targetRef, binding, digest, nil, nil, nil)
	expectedHash, err := platformcrypto.CanonicalSHA256Hex(expected)
	if err != nil {
		t.Fatalf("hash expected: %v", err)
	}

	// A policy matching exactly what derive(D) produces must hash equal.
	honestP := &aiopsv1alpha1.RuntimeSecurityPolicy{}
	honestP.Spec.PlacementDecisionRef = decRef
	honestP.Spec.TargetRef = targetRef
	honestP.Spec.Binding = binding
	honestP.Spec.EnforcementMode = "audit"
	honestP.Spec.Exec = aiopsv1alpha1.ExecPolicy{DefaultAction: "deny"}
	honestP.Spec.FileAccess = aiopsv1alpha1.FileAccessPolicy{DefaultAction: "deny"}
	honestP.Spec.NetworkEgress = aiopsv1alpha1.NetworkEgressPolicy{DefaultAction: "deny"}
	honestP.Spec.DeviceAccess = aiopsv1alpha1.DeviceAccessPolicy{DefaultAction: "deny"}
	honestP.Spec.AgentIntegrity = aiopsv1alpha1.AgentIntegritySpec{ExpectedImageDigest: digest}

	honestHash, err := platformcrypto.CanonicalSHA256Hex(receivedFromPolicy(honestP))
	if err != nil {
		t.Fatalf("hash honest: %v", err)
	}
	if honestHash != expectedHash {
		t.Fatalf("an honestly-derived policy must hash equal to derive(D): got %s want %s", honestHash, expectedHash)
	}

	// A tampered policy -- same identity/binding, but a rogue allow-list
	// added to Exec after derivation -- must hash DIFFERENT.
	tamperedP := honestP.DeepCopy()
	tamperedP.Spec.Exec.AllowedPaths = []string{"/bin/sh"}
	tamperedHash, err := platformcrypto.CanonicalSHA256Hex(receivedFromPolicy(tamperedP))
	if err != nil {
		t.Fatalf("hash tampered: %v", err)
	}
	if tamperedHash == expectedHash {
		t.Fatal("a tampered policy (rogue AllowedPaths entry) must NOT hash equal to derive(D) -- tampering was not detected")
	}

	// A tampered EnforcementMode (audit -> enforce) must also be caught.
	escalatedP := honestP.DeepCopy()
	escalatedP.Spec.EnforcementMode = "enforce"
	escalatedHash, err := platformcrypto.CanonicalSHA256Hex(receivedFromPolicy(escalatedP))
	if err != nil {
		t.Fatalf("hash escalated: %v", err)
	}
	if escalatedHash == expectedHash {
		t.Fatal("a tampered EnforcementMode (audit->enforce) must NOT hash equal to derive(D) -- tampering was not detected")
	}
}

func TestExpectedFromDecisionMirrorsSignedFilePolicyRequest(t *testing.T) {
	decRef := aiopsv1alpha1.ObjectReference{Name: "d-file", Namespace: "workloads"}
	targetRef := aiopsv1alpha1.ObjectReference{Name: "pod-file", Namespace: "workloads"}
	binding := aiopsv1alpha1.PlacementBinding{DecisionID: "workloads/d-file", DecisionVersion: 1, DecisionEpoch: 1}
	digest := "repo@sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"[:64]
	fileReq := &placementtoken.FilePolicyRequest{
		DefaultAction: "deny",
		AllowedPaths:  []string{"/lib/libm.so.6", "/lib/libc.so.6"},
	}

	expected := expectedFromDecision(decRef, targetRef, binding, digest, nil, fileReq, nil)
	honest := &aiopsv1alpha1.RuntimeSecurityPolicy{}
	honest.Spec.PlacementDecisionRef = decRef
	honest.Spec.TargetRef = targetRef
	honest.Spec.Binding = binding
	honest.Spec.EnforcementMode = "audit"
	honest.Spec.Exec = aiopsv1alpha1.ExecPolicy{DefaultAction: "deny"}
	honest.Spec.FileAccess = aiopsv1alpha1.FileAccessPolicy{
		DefaultAction:       "deny",
		AllowedPathPrefixes: []string{"/lib/libm.so.6", "/lib/libc.so.6"},
	}
	honest.Spec.NetworkEgress = aiopsv1alpha1.NetworkEgressPolicy{DefaultAction: "deny"}
	honest.Spec.DeviceAccess = aiopsv1alpha1.DeviceAccessPolicy{DefaultAction: "deny"}
	honest.Spec.AgentIntegrity = aiopsv1alpha1.AgentIntegritySpec{ExpectedImageDigest: digest}

	expectedHash, err := platformcrypto.CanonicalSHA256Hex(expected)
	if err != nil {
		t.Fatalf("hash expected: %v", err)
	}
	honestHash, err := platformcrypto.CanonicalSHA256Hex(receivedFromPolicy(honest))
	if err != nil {
		t.Fatalf("hash honest: %v", err)
	}
	if honestHash != expectedHash {
		t.Fatalf("signed file request drifted between operator and agent: got %s want %s", honestHash, expectedHash)
	}

	tampered := honest.DeepCopy()
	tampered.Spec.FileAccess.AllowedPathPrefixes = append(tampered.Spec.FileAccess.AllowedPathPrefixes, "/etc/shadow")
	tamperedHash, err := platformcrypto.CanonicalSHA256Hex(receivedFromPolicy(tampered))
	if err != nil {
		t.Fatalf("hash tampered: %v", err)
	}
	if tamperedHash == expectedHash {
		t.Fatal("unsigned file allow entry was not detected")
	}
}

func TestReplayLedger_AcceptsFirstAndIdenticalRepeat(t *testing.T) {
	l := NewReplayLedger()
	if err := l.CheckAndRecord("d1", 1, 1, "n1"); err != nil {
		t.Fatalf("first sight should be accepted: %v", err)
	}
	if err := l.CheckAndRecord("d1", 1, 1, "n1"); err != nil {
		t.Fatalf("identical (epoch,version,nonce) repeat should be accepted (idempotent re-poll): %v", err)
	}
}

func TestReplayLedger_AcceptsMonotonicAdvance(t *testing.T) {
	l := NewReplayLedger()
	if err := l.CheckAndRecord("d1", 1, 1, "n1"); err != nil {
		t.Fatalf("first sight should be accepted: %v", err)
	}
	if err := l.CheckAndRecord("d1", 1, 2, "n2"); err != nil {
		t.Fatalf("version advance should be accepted: %v", err)
	}
	if err := l.CheckAndRecord("d1", 2, 1, "n3"); err != nil {
		t.Fatalf("epoch advance should be accepted: %v", err)
	}
}

func TestReplayLedger_RejectsRollback(t *testing.T) {
	l := NewReplayLedger()
	if err := l.CheckAndRecord("d1", 1, 5, "n5"); err != nil {
		t.Fatalf("first sight should be accepted: %v", err)
	}
	if err := l.CheckAndRecord("d1", 1, 3, "n3"); err == nil {
		t.Fatal("version rollback should be rejected")
	}
	if err := l.CheckAndRecord("d1", 0, 5, "n5"); err == nil {
		t.Fatal("epoch rollback should be rejected")
	}
}

func TestReplayLedger_RejectsReplayWithDifferentNonce(t *testing.T) {
	l := NewReplayLedger()
	if err := l.CheckAndRecord("d1", 1, 1, "n1"); err != nil {
		t.Fatalf("first sight should be accepted: %v", err)
	}
	if err := l.CheckAndRecord("d1", 1, 1, "forged-nonce"); err == nil {
		t.Fatal("same (epoch,version) with a different nonce should be rejected as a replay")
	}
}

func TestReplayLedger_TracksDecisionsIndependently(t *testing.T) {
	l := NewReplayLedger()
	if err := l.CheckAndRecord("d1", 1, 5, "n5"); err != nil {
		t.Fatalf("d1 first sight should be accepted: %v", err)
	}
	if err := l.CheckAndRecord("d2", 1, 1, "n1"); err != nil {
		t.Fatalf("d2 first sight should be accepted independently of d1's state: %v", err)
	}
}

// --- Task 12 follow-up: persistent replay ledger ---

func TestReplayLedgerPersistent_SurvivesReload(t *testing.T) {
	path := t.TempDir() + "/ledger.json"

	l1, err := NewReplayLedgerPersistent(path)
	if err != nil {
		t.Fatalf("new persistent ledger: %v", err)
	}
	if err := l1.CheckAndRecord("d1", 2, 7, "n7"); err != nil {
		t.Fatalf("first sight should be accepted: %v", err)
	}

	// Simulate an agent restart on the same node: a fresh ledger loading
	// the same persistPath must remember d1's state, not forget it.
	l2, err := NewReplayLedgerPersistent(path)
	if err != nil {
		t.Fatalf("reload persistent ledger: %v", err)
	}
	if err := l2.CheckAndRecord("d1", 2, 6, "stale"); err == nil {
		t.Fatal("reloaded ledger should still reject a rollback below the persisted (epoch,version)")
	}
	if err := l2.CheckAndRecord("d1", 2, 7, "different-nonce"); err == nil {
		t.Fatal("reloaded ledger should still reject a replay with a different nonce at the persisted (epoch,version)")
	}
	if err := l2.CheckAndRecord("d1", 2, 8, "n8"); err != nil {
		t.Fatalf("reloaded ledger should accept a genuine monotonic advance: %v", err)
	}
}

func TestReplayLedgerPersistent_EmptyFileIsFreshState(t *testing.T) {
	path := t.TempDir() + "/ledger.json"
	l, err := NewReplayLedgerPersistent(path)
	if err != nil {
		t.Fatalf("new persistent ledger with no existing file: %v", err)
	}
	if err := l.CheckAndRecord("d1", 1, 1, "n1"); err != nil {
		t.Fatalf("first sight on a fresh ledger should be accepted: %v", err)
	}
}

// --- Task 12 follow-up: TOFU trust-anchor pinning ---

func newTrustAnchorFakeClient(t *testing.T, pubHex string) client.Client {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("add corev1 to scheme: %v", err)
	}
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "trust-anchor", Namespace: "aiops-system"},
		Data:       map[string]string{"publicKeyHex": pubHex},
	}
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(cm).Build()
}

func genTestKeyHex(t *testing.T, seed byte) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(bytes.NewReader(bytesRepeat(seed, ed25519.SeedSize)))
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return hex.EncodeToString(pub)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestLoadTrustAnchorTOFU_PinsOnFirstUse(t *testing.T) {
	pinPath := t.TempDir() + "/trust-anchor.pin"
	keyHex := genTestKeyHex(t, 0x01)
	c := newTrustAnchorFakeClient(t, keyHex)

	pub, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath)
	if err != nil {
		t.Fatalf("first use should pin successfully: %v", err)
	}
	if hex.EncodeToString(pub) != keyHex {
		t.Fatalf("returned key = %s, want %s", hex.EncodeToString(pub), keyHex)
	}
	if _, err := os.Stat(pinPath); err != nil {
		t.Fatalf("expected pin file to be created: %v", err)
	}
}

func TestLoadTrustAnchorTOFU_AcceptsSameKeyOnSubsequentUse(t *testing.T) {
	pinPath := t.TempDir() + "/trust-anchor.pin"
	keyHex := genTestKeyHex(t, 0x02)
	c := newTrustAnchorFakeClient(t, keyHex)

	if _, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath); err != nil {
		t.Fatalf("first use: %v", err)
	}
	// Simulate a restart: reload against the SAME unchanged ConfigMap.
	pub, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath)
	if err != nil {
		t.Fatalf("second use with an unchanged key should succeed: %v", err)
	}
	if hex.EncodeToString(pub) != keyHex {
		t.Fatalf("returned key = %s, want %s", hex.EncodeToString(pub), keyHex)
	}
}

func TestLoadTrustAnchorTOFU_RejectsChangedKey(t *testing.T) {
	pinPath := t.TempDir() + "/trust-anchor.pin"
	originalKeyHex := genTestKeyHex(t, 0x03)
	c := newTrustAnchorFakeClient(t, originalKeyHex)

	if _, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath); err != nil {
		t.Fatalf("first use: %v", err)
	}

	// Simulate the trust-anchor ConfigMap being swapped to a different key
	// (a compromised control plane, or an unannounced rotation) -- update
	// the SAME fake client's ConfigMap in place.
	changedKeyHex := genTestKeyHex(t, 0x04)
	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "aiops-system", Name: "trust-anchor"}, &cm); err != nil {
		t.Fatalf("get configmap to mutate: %v", err)
	}
	cm.Data["publicKeyHex"] = changedKeyHex
	if err := c.Update(context.Background(), &cm); err != nil {
		t.Fatalf("update configmap: %v", err)
	}

	if _, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath); err == nil {
		t.Fatal("a changed trust-anchor key must be rejected by TOFU pinning, not silently accepted")
	}
}

func TestLoadTrustAnchorTOFU_ReArmsAfterPinFileDeleted(t *testing.T) {
	pinPath := t.TempDir() + "/trust-anchor.pin"
	originalKeyHex := genTestKeyHex(t, 0x05)
	c := newTrustAnchorFakeClient(t, originalKeyHex)

	if _, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath); err != nil {
		t.Fatalf("first use: %v", err)
	}

	changedKeyHex := genTestKeyHex(t, 0x06)
	var cm corev1.ConfigMap
	if err := c.Get(context.Background(), client.ObjectKey{Namespace: "aiops-system", Name: "trust-anchor"}, &cm); err != nil {
		t.Fatalf("get configmap to mutate: %v", err)
	}
	cm.Data["publicKeyHex"] = changedKeyHex
	if err := c.Update(context.Background(), &cm); err != nil {
		t.Fatalf("update configmap: %v", err)
	}

	// The explicit, documented, privileged re-arm path: delete the pin.
	if err := os.Remove(pinPath); err != nil {
		t.Fatalf("remove pin file: %v", err)
	}

	pub, err := LoadTrustAnchorTOFU(context.Background(), c, "aiops-system", "trust-anchor", "publicKeyHex", pinPath)
	if err != nil {
		t.Fatalf("after deleting the pin, the new key should be accepted and re-pinned: %v", err)
	}
	if hex.EncodeToString(pub) != changedKeyHex {
		t.Fatalf("returned key = %s, want %s", hex.EncodeToString(pub), changedKeyHex)
	}
}
