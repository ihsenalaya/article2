#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${TASK08_OUT_DIR:-$REPO_ROOT/results/tasks/TASK-08}"
if [[ "$OUT_DIR" != /* ]]; then
  OUT_DIR="$REPO_ROOT/$OUT_DIR"
fi
mkdir -p "$OUT_DIR/raw-data" "$OUT_DIR/yaml" "$OUT_DIR/stderr"

cat > "$OUT_DIR/raw-data/generate-evidence-fixture.go" <<'GO'
package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/evidence"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: generate-evidence-fixture OUT_DIR")
	}
	outDir := os.Args[1]
	priv, err := crypto.PrivKeyFromHex("0707070707070707070707070707070707070707070707070707070707070707")
	if err != nil {
		panic(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	now := time.Unix(1000, 0).UTC()
	imageDigest := "repo/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	decisionHash := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	policyHash := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	policy := &aiopsv1alpha1.RuntimeSecurityPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: "aiops.imperium.io/v1alpha1", Kind: "RuntimeSecurityPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "guarded-policy", Namespace: "workloads", Generation: 7},
		Spec: aiopsv1alpha1.RuntimeSecurityPolicySpec{
			TargetRef:       aiopsv1alpha1.ObjectReference{Name: "guarded-pod", Namespace: "workloads"},
			Binding:         aiopsv1alpha1.PlacementBinding{DecisionID: "decision-1", PodUID: "pod-uid-1", NodeIdentity: "node-1"},
			AgentIntegrity:  aiopsv1alpha1.AgentIntegritySpec{ExpectedImageDigest: imageDigest},
			Derivation:      aiopsv1alpha1.PolicyDerivationTrace{DecisionHash: decisionHash, PolicyHash: policyHash},
			EnforcementMode: "audit",
		},
	}
	ev := &aiopsv1alpha1.RuntimePlacementEvidence{
		TypeMeta:   metav1.TypeMeta{APIVersion: "aiops.imperium.io/v1alpha1", Kind: "RuntimePlacementEvidence"},
		ObjectMeta: metav1.ObjectMeta{Name: "guarded-policy", Namespace: "aiops-system"},
		Spec: aiopsv1alpha1.RuntimePlacementEvidenceSpec{
			PolicyRef: aiopsv1alpha1.ObjectReference{Name: policy.Name, Namespace: policy.Namespace},
			TargetRef: policy.Spec.TargetRef,
			NodeName:  "node-1",
		},
		Status: aiopsv1alpha1.RuntimePlacementEvidenceStatus{
			DecisionID:       policy.Spec.Binding.DecisionID,
			DecisionHash:     decisionHash,
			PolicyHash:       policyHash,
			PolicyGeneration: policy.Generation,
			MonitorID:        "agent-node-1",
			PodUID:           policy.Spec.Binding.PodUID,
			CgroupID:         "123",
			Conformance:      "conform",
			EvidenceMode:     aiopsv1alpha1.EvidenceModeSimulated,
			AgentIntegrity:   aiopsv1alpha1.AgentIntegrityObserved{ImageDigest: imageDigest, DigestVerified: true},
			Behavior:         aiopsv1alpha1.ObservedBehaviorCounters{ExecAllowed: 1},
			EvidenceSequence: 1,
		},
	}
	payload := evidence.Payload{
		SchemaVersion:       evidence.SchemaVersion,
		PolicyRefName:       ev.Spec.PolicyRef.Name,
		PolicyRefNamespace:  ev.Spec.PolicyRef.Namespace,
		TargetRefName:       ev.Spec.TargetRef.Name,
		TargetRefNamespace:  ev.Spec.TargetRef.Namespace,
		DecisionID:          ev.Status.DecisionID,
		DecisionHash:        ev.Status.DecisionHash,
		PolicyHash:          ev.Status.PolicyHash,
		PolicyGeneration:    ev.Status.PolicyGeneration,
		MonitorID:           ev.Status.MonitorID,
		NodeName:            ev.Spec.NodeName,
		PodUID:              ev.Status.PodUID,
		CgroupID:            ev.Status.CgroupID,
		Conformance:         ev.Status.Conformance,
		EvidenceMode:        string(ev.Status.EvidenceMode),
		AgentImageDigest:    ev.Status.AgentIntegrity.ImageDigest,
		AgentDigestVerified: ev.Status.AgentIntegrity.DigestVerified,
		Behavior:            evidence.BehaviorCounters{ExecAllowed: 1},
		EvidenceSequence:    ev.Status.EvidenceSequence,
		IssuedAt:            now.Unix(),
		ExpiresAt:           now.Add(10 * time.Minute).Unix(),
	}
	sig, err := evidence.Sign(priv, ev.Status.MonitorID, payload)
	if err != nil {
		panic(err)
	}
	ev.Status.Signature = aiopsv1alpha1.EvidenceSignature{
		Algorithm:     sig.Algorithm,
		KeyIdentifier: sig.KeyIdentifier,
		PayloadDigest: sig.PayloadDigest,
		Signature:     sig.SignatureHex,
		IssuedAt:      metav1.NewTime(sig.IssuedAt),
		ExpiresAt:     metav1.NewTime(sig.ExpiresAt),
	}
	writeYAML(filepath.Join(outDir, "yaml", "policy.yaml"), policy)
	writeYAML(filepath.Join(outDir, "yaml", "evidence.yaml"), ev)
	if err := os.WriteFile(filepath.Join(outDir, "raw-data", "agent-public-key.hex"), []byte(crypto.PubKeyToHex(pub)+"\n"), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("fixture_written=true")
}

func writeYAML(path string, obj any) {
	raw, err := yaml.Marshal(obj)
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		panic(err)
	}
}
GO

(cd "$REPO_ROOT/operator" && go run "$OUT_DIR/raw-data/generate-evidence-fixture.go" "$OUT_DIR")
PUBLIC_KEY_HEX="$(cat "$OUT_DIR/raw-data/agent-public-key.hex")"

(cd "$REPO_ROOT/operator" && go run ./cmd/verify-evidence \
  --evidence-file "$OUT_DIR/yaml/evidence.yaml" \
  --policy-file "$OUT_DIR/yaml/policy.yaml" \
  --public-key-hex "$PUBLIC_KEY_HEX" \
  --now-unix 1030 \
  --max-age 1m) | tee "$OUT_DIR/raw-data/verify-evidence-valid-report.json"

set +e
(cd "$REPO_ROOT/operator" && go run ./cmd/verify-evidence \
  --evidence-file "$OUT_DIR/yaml/evidence.yaml" \
  --policy-file "$OUT_DIR/yaml/policy.yaml" \
  --public-key-hex "$PUBLIC_KEY_HEX" \
  --now-unix 1200 \
  --max-age 1m) > "$OUT_DIR/raw-data/verify-evidence-stale-report.json" 2> "$OUT_DIR/stderr/verify-evidence-stale.err"
STALE_EXIT_CODE=$?
set -e
echo "$STALE_EXIT_CODE" > "$OUT_DIR/raw-data/verify-evidence-stale-exit-code.txt"
if [[ "$STALE_EXIT_CODE" -ne 1 ]]; then
  echo "expected stale verification to exit 1, got $STALE_EXIT_CODE" >&2
  exit 1
fi
echo "stale_exit_code=$STALE_EXIT_CODE"
