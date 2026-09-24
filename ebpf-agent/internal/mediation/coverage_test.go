package mediation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type matrix struct {
	SchemaVersion string      `json:"schema_version"`
	Operations    []operation `json:"operations"`
	ReportedGaps  []gap       `json:"reported_gaps"`
}

type operation struct {
	ID             string   `json:"id"`
	PolicyFields   []string `json:"policy_fields"`
	AuditHooks     []string `json:"audit_hooks"`
	EnforceHooks   []string `json:"enforce_hooks"`
	EventType      string   `json:"event_type"`
	BPFSource      string   `json:"bpf_source"`
	PolicyTestFile string   `json:"policy_test_file"`
	PolicyTests    []string `json:"policy_tests"`
	AttackCase     string   `json:"attack_case"`
	RawResult      string   `json:"raw_result"`
	CoverageStatus string   `json:"coverage_status"`
}

type gap struct {
	ID           string `json:"id"`
	ClaimNotMade string `json:"claim_not_made"`
	Reason       string `json:"reason"`
}

func TestMediationCoverageMatrixTraceability(t *testing.T) {
	repoRoot := filepath.Clean(filepath.Join("..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join("testdata", "coverage.json"))
	if err != nil {
		t.Fatalf("read mediation matrix: %v", err)
	}
	var m matrix
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode mediation matrix: %v", err)
	}
	if m.SchemaVersion == "" {
		t.Fatal("schema_version is required")
	}

	required := map[string]bool{
		"exec":            false,
		"file_access":     false,
		"network_connect": false,
		"device_access":   false,
	}
	common, err := os.ReadFile(filepath.Join(repoRoot, "ebpf-agent", "bpf", "common.h"))
	if err != nil {
		t.Fatalf("read common.h: %v", err)
	}

	for _, op := range m.Operations {
		if _, ok := required[op.ID]; ok {
			required[op.ID] = true
		}
		assertNonEmpty(t, op.ID, "policy_fields", op.PolicyFields)
		assertNonEmpty(t, op.ID, "audit_hooks", op.AuditHooks)
		assertNonEmpty(t, op.ID, "enforce_hooks", op.EnforceHooks)
		assertNonEmpty(t, op.ID, "policy_tests", op.PolicyTests)
		for _, field := range op.PolicyFields {
			if !strings.HasPrefix(field, "RuntimeSecurityPolicy.spec.") {
				t.Fatalf("%s policy field %q does not trace to RuntimeSecurityPolicy.spec", op.ID, field)
			}
		}
		bpfSource, err := os.ReadFile(filepath.Join(repoRoot, op.BPFSource))
		if err != nil {
			t.Fatalf("%s read bpf source %s: %v", op.ID, op.BPFSource, err)
		}
		for _, hook := range append(op.AuditHooks, op.EnforceHooks...) {
			if !strings.Contains(string(bpfSource), "SEC(\""+hook+"\")") {
				t.Fatalf("%s hook %q not found in %s", op.ID, hook, op.BPFSource)
			}
		}
		if !strings.Contains(string(bpfSource), op.EventType) {
			t.Fatalf("%s event type %q not emitted/referenced in %s", op.ID, op.EventType, op.BPFSource)
		}
		if !strings.Contains(string(common), op.EventType) {
			t.Fatalf("%s event type %q not found in common.h", op.ID, op.EventType)
		}
		testSource, err := os.ReadFile(filepath.Join(repoRoot, op.PolicyTestFile))
		if err != nil {
			t.Fatalf("%s read policy test file %s: %v", op.ID, op.PolicyTestFile, err)
		}
		for _, testName := range op.PolicyTests {
			if !strings.Contains(string(testSource), "func "+testName+"(") {
				t.Fatalf("%s referenced test %s not found in %s", op.ID, testName, op.PolicyTestFile)
			}
		}
		if op.AttackCase == "" || op.RawResult == "" || op.CoverageStatus == "" {
			t.Fatalf("%s must include attack_case, raw_result, and coverage_status", op.ID)
		}
	}
	for id, seen := range required {
		if !seen {
			t.Fatalf("required protected operation %s missing from mediation matrix", id)
		}
	}
	if len(m.ReportedGaps) == 0 {
		t.Fatal("expected reported gaps for uncovered/limited semantics")
	}
}

func assertNonEmpty(t *testing.T, opID, field string, values []string) {
	t.Helper()
	if len(values) == 0 {
		t.Fatalf("%s must define %s", opID, field)
	}
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			t.Fatalf("%s contains empty %s value", opID, field)
		}
	}
}
