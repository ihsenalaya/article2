package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/internal/upstream"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

const testAgentImageDigest = "example.com/runtime-guard-ebpf-agent@sha256:" +
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func newTestScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatalf("register aiopsv1alpha1 scheme: %v", err)
	}
	if err := upstream.AddToScheme(scheme); err != nil {
		t.Fatalf("register upstream scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		t.Fatalf("register corev1 scheme: %v", err)
	}
	return scheme
}

func mintToken(t *testing.T, priv ed25519.PrivateKey, payload placementtoken.Payload) string {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	tok := placementtoken.Token{Payload: payload, Signature: platformcrypto.Ed25519Sign(priv, data)}
	raw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	return string(raw)
}

func trustAnchorConfigMap(namespace, name, key, pubKeyHex string) *corev1.ConfigMap {
	return &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Data:       map[string]string{key: pubKeyHex},
	}
}

func validPlacementPayload(now time.Time, decisionID string, version int64, nonce string) placementtoken.Payload {
	return placementtoken.Payload{
		DecisionID:      decisionID,
		DecisionVersion: version,
		DecisionEpoch:   1,
		DecisionNonce:   nonce,
		PodUID:          "pod-uid-1",
		PodSpecHash:     "specHash1",
		ImageDigest:     "repo@sha256:workload",
		ModelDigest:     "sha256:model",
		NodeIdentity:    "node-1",
		RuntimeClass:    "kata-qemu-snp",
		EvidenceHash:    "evHash1",
		PolicyHash:      "polHash1",
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(5 * time.Minute).Unix(),
	}
}

func TestReconcile_ValidTokenProducesActivePolicy(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	now := time.Now().UTC()
	payload := validPlacementPayload(now, "workloads/risk-assistant", 1, "nonce-valid")

	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "risk-assistant",
			Namespace: "workloads",
			Annotations: map[string]string{
				placementtoken.AnnotationKey: mintToken(t, priv, payload),
			},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "risk-assistant", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}

	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()

	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	_, err = r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "risk-assistant", Namespace: "workloads"}})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "risk-assistant", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}

	if policy.Status.Decision != "active" {
		t.Fatalf("expected status.decision=active, got %q (reason: %s)", policy.Status.Decision, policy.Status.RejectionReason)
	}
	if policy.Spec.EnforcementMode != "audit" {
		t.Fatalf("expected new policy to start in audit mode, got %q", policy.Spec.EnforcementMode)
	}
	if policy.Spec.Binding.PodUID != "pod-uid-1" {
		t.Fatalf("expected binding.podUID copied from token payload, got %q", policy.Spec.Binding.PodUID)
	}
	if policy.Spec.Binding.DecisionID != payload.DecisionID {
		t.Fatalf("expected binding.decisionID copied from token payload, got %q", policy.Spec.Binding.DecisionID)
	}
	if policy.Spec.Derivation.DerivationVersion != PolicyDerivationVersion {
		t.Fatalf("expected derivation version %q, got %q", PolicyDerivationVersion, policy.Spec.Derivation.DerivationVersion)
	}
	if policy.Spec.Derivation.DecisionHash == "" || policy.Spec.Derivation.PolicyHash == "" || policy.Spec.Derivation.TokenHash == "" {
		t.Fatalf("expected non-empty derivation hashes, got %+v", policy.Spec.Derivation)
	}
	if policy.Spec.Derivation.EvidenceHash != payload.EvidenceHash {
		t.Fatalf("expected evidence hash linked from token payload, got %q", policy.Spec.Derivation.EvidenceHash)
	}
	if policy.Spec.AgentIntegrity.ExpectedImageDigest != testAgentImageDigest {
		t.Fatalf("expected agent image digest to be stamped, got %q", policy.Spec.AgentIntegrity.ExpectedImageDigest)
	}
	if len(policy.OwnerReferences) != 1 || policy.OwnerReferences[0].Kind != "AIPlacementDecision" {
		t.Fatalf("expected an AIPlacementDecision owner reference, got %+v", policy.OwnerReferences)
	}
}

func TestReconcile_MissingTokenIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	pub, _, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{Name: "no-token-pod", Namespace: "workloads"},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "no-token-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()

	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "no-token-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "no-token-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" {
		t.Fatalf("expected status.decision=rejected, got %q", policy.Status.Decision)
	}
}

func TestReconcile_TamperedTokenIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	payload := validPlacementPayload(now, "workloads/tampered-pod", 1, "nonce-tampered")
	payload.PodUID = "pod-uid-2"
	rawToken := mintToken(t, priv, payload)

	// Tamper: swap in a different node identity after signing, without re-signing.
	var tok placementtoken.Token
	if err := json.Unmarshal([]byte(rawToken), &tok); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	tok.Payload.NodeIdentity = "attacker-node"
	tamperedRaw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal tampered token: %v", err)
	}

	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tampered-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: string(tamperedRaw)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "tampered-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()

	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "tampered-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "tampered-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" {
		t.Fatalf("expected tampered token to be rejected, got decision=%q reason=%q", policy.Status.Decision, policy.Status.RejectionReason)
	}
}

func TestReconcile_WrongSigningKeyIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	trustedPub, _, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate trusted key pair: %v", err)
	}
	_, attackerPriv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate attacker key pair: %v", err)
	}
	payload := validPlacementPayload(time.Now().UTC(), "workloads/wrong-key-pod", 1, "nonce-wrong-key")
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "wrong-key-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, attackerPriv, payload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "wrong-key-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(trustedPub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "wrong-key-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "wrong-key-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" {
		t.Fatalf("expected wrong-key token to be rejected, got decision=%q reason=%q", policy.Status.Decision, policy.Status.RejectionReason)
	}
}

func TestReconcile_ExpiredTokenIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	payload := validPlacementPayload(now, "workloads/expired-pod", 1, "nonce-expired")
	payload.IssuedAt = now.Add(-10 * time.Minute).Unix()
	payload.ExpiresAt = now.Add(-5 * time.Minute).Unix()
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "expired-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, priv, payload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "expired-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "expired-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "expired-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" {
		t.Fatalf("expected expired token to be rejected, got decision=%q reason=%q", policy.Status.Decision, policy.Status.RejectionReason)
	}
}

func TestReconcile_ReplayedDecisionIDIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	payload := validPlacementPayload(now, "stable-decision-id", 1, "nonce-replay")
	firstDecision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, priv, payload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "first-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	secondDecision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "second-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, priv, payload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "second-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(firstDecision, secondDecision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "first-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile first decision: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "second-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile replayed decision: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "second-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" || policy.Status.RejectionReason == "" {
		t.Fatalf("expected replayed decision to be rejected, got decision=%q reason=%q", policy.Status.Decision, policy.Status.RejectionReason)
	}
}

func TestReconcile_OlderVersionRollbackIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}
	now := time.Now().UTC()
	currentPayload := validPlacementPayload(now, "workloads/rollback-pod", 2, "nonce-version-2")
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rollback-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, priv, currentPayload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "rollback-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	key := types.NamespacedName{Name: "rollback-pod", Namespace: "workloads"}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile current version: %v", err)
	}

	var updated upstream.AIPlacementDecision
	if err := c.Get(context.Background(), key, &updated); err != nil {
		t.Fatalf("get decision: %v", err)
	}
	olderPayload := validPlacementPayload(now, "workloads/rollback-pod", 1, "nonce-version-1")
	updated.Annotations[placementtoken.AnnotationKey] = mintToken(t, priv, olderPayload)
	if err := c.Update(context.Background(), &updated); err != nil {
		t.Fatalf("update decision with older version: %v", err)
	}
	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile older version: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), key, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" || policy.Status.RejectionReason == "" {
		t.Fatalf("expected rollback to be rejected, got decision=%q reason=%q", policy.Status.Decision, policy.Status.RejectionReason)
	}
}

func TestReconcile_RevokedDecisionIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{Name: "revoked-pod", Namespace: "workloads"},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "revoked-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "revoked"},
	}
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:           c,
		AgentImageDigest: testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "revoked-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "revoked-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" || policy.Status.RejectionReason == "" {
		t.Fatalf("expected revoked decision to be rejected, got decision=%q reason=%q", policy.Status.Decision, policy.Status.RejectionReason)
	}
}

func TestReconcile_UpstreamNotAllowIsRejected(t *testing.T) {
	scheme := newTestScheme(t)
	pub, _, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{Name: "denied-pod", Namespace: "workloads"},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "denied-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "deny"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))

	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()

	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "denied-pod", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), types.NamespacedName{Name: "denied-pod", Namespace: "workloads"}, &policy); err != nil {
		t.Fatalf("get generated policy: %v", err)
	}
	if policy.Status.Decision != "rejected" {
		t.Fatalf("expected status.decision=rejected for upstream deny, got %q", policy.Status.Decision)
	}
}

func TestReconcile_MissingAgentImageDigestSkipsGeneration(t *testing.T) {
	scheme := newTestScheme(t)
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{Name: "no-agent-digest", Namespace: "workloads"},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "no-agent-digest", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}

	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(decision).Build()
	r := &AIPlacementDecisionReconciler{Client: c} // AgentImageDigest intentionally unset

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Name: "no-agent-digest", Namespace: "workloads"}}); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	err := c.Get(context.Background(), types.NamespacedName{Name: "no-agent-digest", Namespace: "workloads"}, &policy)
	if err == nil {
		t.Fatal("expected no RuntimeSecurityPolicy to be generated when AgentImageDigest is unset")
	}
}

func TestReconcile_SameDecisionProducesEquivalentPolicyDeterministically(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	payload := validPlacementPayload(time.Now().UTC(), "workloads/deterministic-pod", 1, "nonce-deterministic")
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "deterministic-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, priv, payload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "deterministic-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}
	key := types.NamespacedName{Name: "deterministic-pod", Namespace: "workloads"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	var first aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), key, &first); err != nil {
		t.Fatalf("get first policy: %v", err)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	var second aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), key, &second); err != nil {
		t.Fatalf("get second policy: %v", err)
	}

	if !reflect.DeepEqual(first.Spec, second.Spec) {
		t.Fatalf("same decision produced different policy specs:\nfirst=%+v\nsecond=%+v", first.Spec, second.Spec)
	}
}

func TestReconcile_AlteredDecisionCannotReuseStalePolicy(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	now := time.Now().UTC()
	firstPayload := validPlacementPayload(now, "workloads/stale-pod", 1, "nonce-stale-1")
	firstPayload.NodeIdentity = "node-old"
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "stale-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: mintToken(t, priv, firstPayload)},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "stale-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}
	key := types.NamespacedName{Name: "stale-pod", Namespace: "workloads"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile first decision: %v", err)
	}
	var firstPolicy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), key, &firstPolicy); err != nil {
		t.Fatalf("get first policy: %v", err)
	}

	var updated upstream.AIPlacementDecision
	if err := c.Get(context.Background(), key, &updated); err != nil {
		t.Fatalf("get decision: %v", err)
	}
	secondPayload := validPlacementPayload(now, "workloads/stale-pod", 2, "nonce-stale-2")
	secondPayload.NodeIdentity = "node-new"
	secondPayload.PodSpecHash = "specHash2"
	updated.Annotations[placementtoken.AnnotationKey] = mintToken(t, priv, secondPayload)
	if err := c.Update(context.Background(), &updated); err != nil {
		t.Fatalf("update decision: %v", err)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile altered decision: %v", err)
	}
	var secondPolicy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), key, &secondPolicy); err != nil {
		t.Fatalf("get second policy: %v", err)
	}

	if secondPolicy.Status.Decision != "active" {
		t.Fatalf("expected altered valid decision to remain active, got %q reason=%q", secondPolicy.Status.Decision, secondPolicy.Status.RejectionReason)
	}
	if secondPolicy.Spec.Binding.NodeIdentity != "node-new" || secondPolicy.Spec.Binding.PodSpecHash != "specHash2" {
		t.Fatalf("expected policy binding regenerated from altered decision, got %+v", secondPolicy.Spec.Binding)
	}
	if firstPolicy.Spec.Derivation.DecisionHash == secondPolicy.Spec.Derivation.DecisionHash {
		t.Fatalf("expected altered D to change decision hash %q", secondPolicy.Spec.Derivation.DecisionHash)
	}
	if firstPolicy.Spec.Derivation.PolicyHash == secondPolicy.Spec.Derivation.PolicyHash {
		t.Fatalf("expected altered D to change derived policy hash %q", secondPolicy.Spec.Derivation.PolicyHash)
	}
}

func TestReconcile_RejectedDecisionClearsStalePolicyBinding(t *testing.T) {
	scheme := newTestScheme(t)
	pub, priv, err := platformcrypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("generate key pair: %v", err)
	}

	payload := validPlacementPayload(time.Now().UTC(), "workloads/clear-stale-pod", 1, "nonce-clear-stale")
	rawToken := mintToken(t, priv, payload)
	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name: "clear-stale-pod", Namespace: "workloads",
			Annotations: map[string]string{placementtoken.AnnotationKey: rawToken},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef: upstream.ObjectRef{Name: "clear-stale-pod", Namespace: "workloads"},
			PolicyRef: upstream.ObjectRef{Name: "e2e-policy", Namespace: "workloads"},
		},
		Status: upstream.AIPlacementDecisionStatus{Decision: "allow"},
	}
	cm := trustAnchorConfigMap("aiops-system", "attestation-scheduler-public-key", "publicKeyHex", platformcrypto.PubKeyToHex(pub))
	c := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(decision, cm).
		WithStatusSubresource(&aiopsv1alpha1.RuntimeSecurityPolicy{}).
		Build()
	r := &AIPlacementDecisionReconciler{
		Client:                   c,
		TrustAnchorNamespace:     "aiops-system",
		TrustAnchorConfigMapName: "attestation-scheduler-public-key",
		TrustAnchorConfigMapKey:  "publicKeyHex",
		AgentImageDigest:         testAgentImageDigest,
	}
	key := types.NamespacedName{Name: "clear-stale-pod", Namespace: "workloads"}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile valid decision: %v", err)
	}

	var updated upstream.AIPlacementDecision
	if err := c.Get(context.Background(), key, &updated); err != nil {
		t.Fatalf("get decision: %v", err)
	}
	var tok placementtoken.Token
	if err := json.Unmarshal([]byte(rawToken), &tok); err != nil {
		t.Fatalf("unmarshal token: %v", err)
	}
	tok.Payload.NodeIdentity = "tampered-node"
	tamperedRaw, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal tampered token: %v", err)
	}
	updated.Annotations[placementtoken.AnnotationKey] = string(tamperedRaw)
	if err := c.Update(context.Background(), &updated); err != nil {
		t.Fatalf("update decision: %v", err)
	}

	if _, err := r.Reconcile(context.Background(), ctrl.Request{NamespacedName: key}); err != nil {
		t.Fatalf("reconcile tampered decision: %v", err)
	}
	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := c.Get(context.Background(), key, &policy); err != nil {
		t.Fatalf("get policy: %v", err)
	}
	if policy.Status.Decision != "rejected" {
		t.Fatalf("expected tampered decision rejected, got %q", policy.Status.Decision)
	}
	if policy.Spec.Binding.DecisionID != "" || policy.Spec.Derivation.PolicyHash != "" {
		t.Fatalf("expected stale binding and derivation cleared after rejection, got binding=%+v derivation=%+v", policy.Spec.Binding, policy.Spec.Derivation)
	}
}
