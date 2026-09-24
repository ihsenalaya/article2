package main

import (
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"sigs.k8s.io/yaml"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/evidence"
)

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type verificationReport struct {
	Valid            bool                `json:"valid"`
	FreshnessSeconds int64               `json:"freshness_seconds"`
	Checks           []verificationCheck `json:"checks"`
	// AuthorizedAndCompliant is Task 06/C4's explicit answer to "can this
	// evidence be read as a positive attestation that the workload is
	// BOTH currently authorized AND behaviorally compliant" -- computed
	// as authorizationState=="authorized" && conformance=="conform"
	// (with authorization-currency, if checked, also required). This is
	// deliberately reported separately from Valid: a correctly-signed,
	// fresh evidence object honestly reporting a REVOKED-but-quiescent
	// workload is not an invalid/untrustworthy evidence object (Valid can
	// still be true), but it must never be mistaken for "authorized and
	// compliant" by a caller who only checks Valid.
	AuthorizedAndCompliant bool `json:"authorized_and_compliant"`
}

type verificationCheck struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

func main() {
	var (
		evidenceFile = flag.String("evidence-file", "", "RuntimePlacementEvidence JSON/YAML file")
		policyFile   = flag.String("policy-file", "", "RuntimeSecurityPolicy JSON/YAML file used as the independent D/P binding reference")
		publicKeyHex = flag.String("public-key-hex", os.Getenv("AGENT_PUBLIC_KEY_HEX"), "hex-encoded Ed25519 public key for the evidence signer")
		maxAge       = flag.Duration("max-age", 15*time.Minute, "maximum accepted age for evidence freshness")
		maxAuthAge   = flag.Duration("max-authorization-age", 15*time.Second, "maximum accepted staleness for the agent's last-confirmed-authorized poll (Task 06/C5); set to 0 to disable this check. Default is 3x the agent's default --poll-interval (5s), giving margin for jitter -- see Task 05/B3's lesson on under-margined freshness thresholds against a fixed polling/ticking cadence")
		nowUnix      = flag.Int64("now-unix", 0, "test/reproducibility override for current Unix timestamp")
	)
	flag.Parse()

	if *evidenceFile == "" || *policyFile == "" || *publicKeyHex == "" {
		fmt.Fprintln(os.Stderr, "evidence-file, policy-file, and public-key-hex are required")
		os.Exit(2)
	}
	now := time.Now().UTC()
	if *nowUnix != 0 {
		now = time.Unix(*nowUnix, 0).UTC()
	}

	report, err := verifyFiles(*evidenceFile, *policyFile, *publicKeyHex, now, *maxAge, *maxAuthAge)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal report:", err)
		os.Exit(2)
	}
	fmt.Println(string(encoded))
	if !report.Valid {
		os.Exit(1)
	}
}

func verifyFiles(evidenceFile, policyFile, publicKeyHex string, now time.Time, maxAge, maxAuthAge time.Duration) (verificationReport, error) {
	var ev aiopsv1alpha1.RuntimePlacementEvidence
	if err := readYAMLOrJSON(evidenceFile, &ev); err != nil {
		return verificationReport{}, fmt.Errorf("read evidence: %w", err)
	}
	var policy aiopsv1alpha1.RuntimeSecurityPolicy
	if err := readYAMLOrJSON(policyFile, &policy); err != nil {
		return verificationReport{}, fmt.Errorf("read policy: %w", err)
	}
	pub, err := crypto.PubKeyFromHex(publicKeyHex)
	if err != nil {
		return verificationReport{}, fmt.Errorf("parse public key: %w", err)
	}
	return verifyEvidence(&ev, &policy, pub, now.UTC(), maxAge, maxAuthAge), nil
}

func readYAMLOrJSON(path string, out any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(raw, out); err != nil {
		return err
	}
	return nil
}

func verifyEvidence(ev *aiopsv1alpha1.RuntimePlacementEvidence, policy *aiopsv1alpha1.RuntimeSecurityPolicy, pubKey ed25519.PublicKey, now time.Time, maxAge, maxAuthAge time.Duration) verificationReport {
	report := verificationReport{Valid: true}
	add := func(name string, passed bool, message string) {
		report.Checks = append(report.Checks, verificationCheck{Name: name, Passed: passed, Message: message})
		if !passed {
			report.Valid = false
		}
	}

	payload := evidence.PayloadFromObject(ev)
	sig := evidence.SignatureFromObject(ev)
	report.FreshnessSeconds = now.Unix() - payload.IssuedAt

	add("signature-algorithm", sig.Algorithm == "ed25519", fmt.Sprintf("algorithm=%q", sig.Algorithm))
	add("monitor-id", ev.Status.MonitorID != "" && ev.Status.MonitorID == sig.KeyIdentifier, fmt.Sprintf("monitorID=%q keyIdentifier=%q", ev.Status.MonitorID, sig.KeyIdentifier))
	if err := evidence.Verify(pubKey, payload, sig); err != nil {
		add("signature", false, err.Error())
	} else {
		add("signature", true, "payload digest and Ed25519 signature verified")
	}

	add("freshness-issued", payload.IssuedAt > 0 && !time.Unix(payload.IssuedAt, 0).After(now.Add(time.Minute)), fmt.Sprintf("issuedAt=%d now=%d", payload.IssuedAt, now.Unix()))
	expiresAt := time.Unix(payload.ExpiresAt, 0)
	add("freshness-expires", payload.ExpiresAt > 0 && (now.Before(expiresAt) || now.Equal(expiresAt)), fmt.Sprintf("expiresAt=%d now=%d", payload.ExpiresAt, now.Unix()))
	if maxAge > 0 {
		add("freshness-max-age", report.FreshnessSeconds >= 0 && report.FreshnessSeconds <= int64(maxAge.Seconds()), fmt.Sprintf("age=%ds max=%ds", report.FreshnessSeconds, int64(maxAge.Seconds())))
	}
	add("freshness-sequence", ev.Status.EvidenceSequence > 0, fmt.Sprintf("sequence=%d", ev.Status.EvidenceSequence))
	if ev.Status.PreviousEvidenceDigest != "" {
		add("freshness-previous-digest", digestPattern.MatchString(ev.Status.PreviousEvidenceDigest), "previous digest is present and well formed")
	} else {
		add("freshness-previous-digest", ev.Status.EvidenceSequence == 1, "previous digest may be empty only for first evidence")
	}

	policyRefMatches := ev.Spec.PolicyRef.Name == policy.Name && ev.Spec.PolicyRef.Namespace == policy.Namespace
	add("policy-ref", policyRefMatches, fmt.Sprintf("evidence=%s/%s policy=%s/%s", ev.Spec.PolicyRef.Namespace, ev.Spec.PolicyRef.Name, policy.Namespace, policy.Name))
	targetRefMatches := ev.Spec.TargetRef.Name == policy.Spec.TargetRef.Name && ev.Spec.TargetRef.Namespace == policy.Spec.TargetRef.Namespace
	add("target-ref", targetRefMatches, fmt.Sprintf("evidence=%s/%s policy=%s/%s", ev.Spec.TargetRef.Namespace, ev.Spec.TargetRef.Name, policy.Spec.TargetRef.Namespace, policy.Spec.TargetRef.Name))
	add("decision-id", ev.Status.DecisionID != "" && ev.Status.DecisionID == policy.Spec.Binding.DecisionID, fmt.Sprintf("evidence=%q policy=%q", ev.Status.DecisionID, policy.Spec.Binding.DecisionID))
	add("decision-hash", digestPattern.MatchString(ev.Status.DecisionHash) && ev.Status.DecisionHash == policy.Spec.Derivation.DecisionHash, fmt.Sprintf("evidence=%q policy=%q", ev.Status.DecisionHash, policy.Spec.Derivation.DecisionHash))
	add("policy-hash", digestPattern.MatchString(ev.Status.PolicyHash) && ev.Status.PolicyHash == policy.Spec.Derivation.PolicyHash, fmt.Sprintf("evidence=%q policy=%q", ev.Status.PolicyHash, policy.Spec.Derivation.PolicyHash))
	add("policy-generation", ev.Status.PolicyGeneration > 0 && ev.Status.PolicyGeneration == policy.Generation, fmt.Sprintf("evidence=%d policy=%d", ev.Status.PolicyGeneration, policy.Generation))

	if policy.Spec.Binding.PodUID != "" {
		add("pod-uid", ev.Status.PodUID == policy.Spec.Binding.PodUID, fmt.Sprintf("evidence=%q policy=%q", ev.Status.PodUID, policy.Spec.Binding.PodUID))
	}
	if policy.Spec.Binding.NodeIdentity != "" {
		add("node-identity", ev.Spec.NodeName == policy.Spec.Binding.NodeIdentity, fmt.Sprintf("evidence=%q policy=%q", ev.Spec.NodeName, policy.Spec.Binding.NodeIdentity))
	}
	add("agent-image-digest", ev.Status.AgentIntegrity.DigestVerified && ev.Status.AgentIntegrity.ImageDigest == policy.Spec.AgentIntegrity.ExpectedImageDigest, fmt.Sprintf("evidence=%q expected=%q verified=%t", ev.Status.AgentIntegrity.ImageDigest, policy.Spec.AgentIntegrity.ExpectedImageDigest, ev.Status.AgentIntegrity.DigestVerified))

	// Task 05 (Observation Completeness), Q3/Q5: these fields are evaluated,
	// not merely carried through. "incomplete" MUST fail verification -- a
	// verifier that accepted incomplete evidence as if it were a normal
	// conform/violation verdict would defeat the entire point of the
	// distinction (experiment protocol Task 05 B1). Similarly, a stale heartbeat
	// means the monitor's own liveness cannot be confirmed as of `now`, so
	// its conformance claim (even "conform") cannot be trusted either.
	add("observation-completeness", ev.Status.Conformance != "incomplete",
		fmt.Sprintf("conformance=%q eventsDroppedSinceLastEvidence=%d dropCount=%d", ev.Status.Conformance, ev.Status.EventsDroppedSinceLastEvidence, ev.Status.DropCount))
	if maxAge > 0 && !ev.Status.LastHeartbeat.IsZero() {
		heartbeatAge := now.Unix() - ev.Status.LastHeartbeat.Time.UTC().Unix()
		add("monitor-heartbeat-fresh", heartbeatAge >= 0 && heartbeatAge <= int64(maxAge.Seconds()),
			fmt.Sprintf("lastHeartbeat=%d now=%d ageSeconds=%d maxSeconds=%d", ev.Status.LastHeartbeat.Time.UTC().Unix(), now.Unix(), heartbeatAge, int64(maxAge.Seconds())))
	} else {
		add("monitor-heartbeat-fresh", false, "lastHeartbeat is unset -- monitor liveness cannot be confirmed")
	}
	add("monitor-epoch-present", ev.Status.MonitorEpoch != "", fmt.Sprintf("monitorEpoch=%q", ev.Status.MonitorEpoch))
	add("hook-set-digest-present", ev.Status.HookSetDigest != "", fmt.Sprintf("hookSetDigest=%q", ev.Status.HookSetDigest))

	// Task 06/C4-C5: RuntimeCompliance (Conformance, above) and
	// AuthorizationValidity are deliberately separate claims -- a
	// workload can be conform (no policy violations observed) while its
	// underlying decision D has been revoked (e.g. idle post-revocation),
	// and neither field implies the other. authorization-currency bounds
	// how stale the agent's own "still authorized" belief can be: the
	// agent cannot know about a revocation more recent than its own last
	// successful poll (default 5s cadence), so this is a measured,
	// explicit upper bound on staleness under an honest-but-possibly-slow
	// control plane -- NOT a cryptographic guarantee against a malicious
	// control plane suppressing or delaying the revocation signal itself
	// (revocation is unauthenticated Kubernetes API state; see Task 06
	// summary.md for the full trust-boundary discussion, C5).
	authCurrencySeconds := int64(-1)
	authStateValid := ev.Status.AuthorizationState == "authorized" || ev.Status.AuthorizationState == "revoked"
	add("authorization-state-present", authStateValid, fmt.Sprintf("authorizationState=%q", ev.Status.AuthorizationState))
	if maxAuthAge > 0 && !ev.Status.LastAuthorizationSync.IsZero() {
		authCurrencySeconds = now.Unix() - ev.Status.LastAuthorizationSync.Time.UTC().Unix()
		add("authorization-currency", authCurrencySeconds >= 0 && authCurrencySeconds <= int64(maxAuthAge.Seconds()),
			fmt.Sprintf("lastAuthorizationSync=%d now=%d ageSeconds=%d maxSeconds=%d", ev.Status.LastAuthorizationSync.Time.UTC().Unix(), now.Unix(), authCurrencySeconds, int64(maxAuthAge.Seconds())))
	} else if maxAuthAge > 0 {
		add("authorization-currency", false, "lastAuthorizationSync is unset -- authorization currency cannot be confirmed")
	}

	report.AuthorizedAndCompliant = ev.Status.AuthorizationState == "authorized" &&
		ev.Status.Conformance == "conform" &&
		(maxAuthAge <= 0 || (authCurrencySeconds >= 0 && authCurrencySeconds <= int64(maxAuthAge.Seconds())))

	return report
}
