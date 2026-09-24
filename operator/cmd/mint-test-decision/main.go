// Command mint-test-decision mints a signed article-1-style placement token
// and prints a ready-to-apply AIPlacementDecision YAML manifest embedding it
// in the ai.sovereign.io/placement-token annotation. Test/experiment tooling
// only: real deployments get this object from article 1's actual scheduler,
// never from this tool — it exists so Phase 5 (kind functional validation)
// can exercise the Runtime Guard Operator's verify-then-generate pipeline
// against a real, correctly-signed artifact without needing article 1's
// whole operator/scheduler running in the same cluster.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

// splitCSV returns nil (not an empty slice) for "", so an unset policy flag
// leaves the request's omitempty field genuinely absent rather than an
// empty-but-present JSON array.
func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// splitCSVInt32 is splitCSV for comma-separated port numbers.
func splitCSVInt32(s string) []int32 {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]int32, 0, len(parts))
	for _, p := range parts {
		v, err := strconv.Atoi(strings.TrimSpace(p))
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid port %q: %v\n", p, err)
			os.Exit(1)
		}
		out = append(out, int32(v))
	}
	return out
}

func main() {
	var (
		privKeyHex   = flag.String("priv-key-hex", os.Getenv("TRUST_ANCHOR_PRIVATE_KEY_HEX"), "hex-encoded Ed25519 private key seed (scheduler signing key)")
		name         = flag.String("name", "", "AIPlacementDecision object name (required)")
		namespace    = flag.String("namespace", "default", "AIPlacementDecision object namespace")
		decisionID   = flag.String("decision-id", "", "immutable signed decision identity; defaults to namespace/name")
		version      = flag.Int64("decision-version", 1, "monotonic signed decision version")
		epoch        = flag.Int64("decision-epoch", 1, "monotonic signed decision epoch")
		nonce        = flag.String("decision-nonce", "", "signed replay-prevention nonce; defaults to current nanosecond timestamp")
		targetName   = flag.String("target-name", "", "target pod/workload name (required)")
		podUID       = flag.String("pod-uid", "", "pod UID this token is bound to (required)")
		podSpecHash  = flag.String("pod-spec-hash", "test-pod-spec-hash", "pod spec hash")
		imageDigest  = flag.String("image-digest", "test-image-digest", "workload image digest")
		modelDigest  = flag.String("model-digest", "test-model-digest", "model weights digest")
		nodeIdentity = flag.String("node-identity", "", "node identity (required, must match the real k8s node name for the agent's poll loop to resolve the pod)")
		runtimeClass = flag.String("runtime-class", "kata-qemu-snp", "runtime class")
		evidenceHash = flag.String("evidence-hash", "test-evidence-hash", "evidence hash")
		policyHash   = flag.String("policy-hash", "test-policy-hash", "policy hash")
		ttl          = flag.Duration("ttl", 30*time.Minute, "token validity duration")
		status       = flag.String("status-decision", "allow", "AIPlacementDecision status.decision to print")
		tamperNode   = flag.String("tamper-node-identity-after-signing", "", "test-only: change node identity after signing")
		signature    = flag.String("signature-override", "", "test-only: override token signature after signing")
		execEnforce  = flag.String("exec-enforcement-mode", "", "optional: request \"audit\" or \"enforce\" for the derived policy's exec hook (default: audit, unchanged)")
		execDefault  = flag.String("exec-default-action", "", "optional: request \"allow\" or \"deny\" as the derived exec policy's default action (default: deny, unchanged)")
		execAllowed  = flag.String("exec-allowed-paths", "", "optional: comma-separated absolute binary paths to allow via the derived exec policy")
		execDenied   = flag.String("exec-denied-paths", "", "optional: comma-separated absolute binary paths to explicitly deny via the derived exec policy")
		fileDefault  = flag.String("file-default-action", "", "optional: request \"allow\" or \"deny\" as the derived file policy's default action (default: deny, unchanged)")
		fileAllowed  = flag.String("file-allowed-paths", "", "optional: comma-separated absolute file paths to allow via the derived file policy")
		fileDenied   = flag.String("file-denied-paths", "", "optional: comma-separated absolute file paths to explicitly deny via the derived file policy")
		netDefault   = flag.String("network-default-action", "", "optional: request \"allow\" or \"deny\" as the derived network policy's default action (default: deny, unchanged)")
		netAllowed   = flag.String("network-allowed-cidrs", "", "optional: comma-separated /32 IPv4 CIDRs (or bare IPs) to allow via the derived network policy")
		netDenied    = flag.String("network-denied-cidrs", "", "optional: comma-separated /32 IPv4 CIDRs (or bare IPs) to explicitly deny via the derived network policy")
		netPorts     = flag.String("network-allowed-ports", "", "optional: comma-separated destination ports restricting the allowed CIDRs above (empty means any port)")
	)
	flag.Parse()

	if *privKeyHex == "" || *name == "" || *targetName == "" || *podUID == "" || *nodeIdentity == "" {
		fmt.Fprintln(os.Stderr, "priv-key-hex, name, target-name, pod-uid, and node-identity are all required")
		os.Exit(1)
	}
	if *decisionID == "" {
		*decisionID = fmt.Sprintf("%s/%s", *namespace, *name)
	}
	if *nonce == "" {
		*nonce = fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}

	priv, err := platformcrypto.PrivKeyFromHex(*privKeyHex)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid private key:", err)
		os.Exit(1)
	}

	now := time.Now().UTC()
	payload := placementtoken.Payload{
		DecisionID:      *decisionID,
		DecisionVersion: *version,
		DecisionEpoch:   *epoch,
		DecisionNonce:   *nonce,
		PodUID:          *podUID,
		PodSpecHash:     *podSpecHash,
		ImageDigest:     *imageDigest,
		ModelDigest:     *modelDigest,
		NodeIdentity:    *nodeIdentity,
		RuntimeClass:    *runtimeClass,
		EvidenceHash:    *evidenceHash,
		PolicyHash:      *policyHash,
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(*ttl).Unix(),
	}
	if *execEnforce != "" || *execDefault != "" || *execAllowed != "" || *execDenied != "" {
		payload.ExecPolicyRequest = &placementtoken.ExecPolicyRequest{
			EnforcementMode: *execEnforce,
			DefaultAction:   *execDefault,
			AllowedPaths:    splitCSV(*execAllowed),
			DeniedPaths:     splitCSV(*execDenied),
		}
	}
	if *fileDefault != "" || *fileAllowed != "" || *fileDenied != "" {
		payload.FilePolicyRequest = &placementtoken.FilePolicyRequest{
			DefaultAction: *fileDefault,
			AllowedPaths:  splitCSV(*fileAllowed),
			DeniedPaths:   splitCSV(*fileDenied),
		}
	}
	if *netDefault != "" || *netAllowed != "" || *netDenied != "" || *netPorts != "" {
		payload.NetworkPolicyRequest = &placementtoken.NetworkPolicyRequest{
			DefaultAction: *netDefault,
			AllowedCIDRs:  splitCSV(*netAllowed),
			DeniedCIDRs:   splitCSV(*netDenied),
			AllowedPorts:  splitCSVInt32(*netPorts),
		}
	}
	data, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal payload:", err)
		os.Exit(1)
	}
	tok := placementtoken.Token{Payload: payload, Signature: platformcrypto.Ed25519Sign(priv, data)}
	if *tamperNode != "" {
		tok.Payload.NodeIdentity = *tamperNode
	}
	if *signature != "" {
		tok.Signature = *signature
	}
	tokJSON, err := json.Marshal(tok)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal token:", err)
		os.Exit(1)
	}

	annotationValue, err := json.Marshal(string(tokJSON))
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal annotation value:", err)
		os.Exit(1)
	}

	fmt.Printf(`apiVersion: aiops.imperium.io/v1alpha1
kind: AIPlacementDecision
metadata:
  name: %s
  namespace: %s
  annotations:
    ai.sovereign.io/placement-token: %s
spec:
  targetRef:
    name: %s
    namespace: %s
  policyRef:
    name: test-policy
    namespace: %s
  schedulerName: ai-attestation-scheduler
status:
  decision: %s
`, *name, *namespace, string(annotationValue), *targetName, *namespace, *namespace, *status)
}
