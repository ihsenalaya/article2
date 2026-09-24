package policy

import (
	"testing"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"

	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/pathhash"
)

func minimalPolicy() *aiopsv1alpha1.RuntimeSecurityPolicy {
	return &aiopsv1alpha1.RuntimeSecurityPolicy{
		Spec: aiopsv1alpha1.RuntimeSecurityPolicySpec{
			Exec:          aiopsv1alpha1.ExecPolicy{DefaultAction: "deny"},
			FileAccess:    aiopsv1alpha1.FileAccessPolicy{DefaultAction: "deny"},
			NetworkEgress: aiopsv1alpha1.NetworkEgressPolicy{DefaultAction: "deny"},
			DeviceAccess:  aiopsv1alpha1.DeviceAccessPolicy{DefaultAction: "deny"},
		},
	}
}

func TestBuildPlan_DefaultActionsTranslated(t *testing.T) {
	p := minimalPolicy()
	p.Spec.Exec.DefaultAction = "allow"
	p.Spec.NetworkEgress.DefaultAction = "allow"

	plan, skipped, err := BuildPlan(42, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped CIDRs, got %+v", skipped)
	}
	if !plan.Config.ExecDefaultAllow {
		t.Error("expected ExecDefaultAllow=true")
	}
	if plan.Config.FileDefaultAllow {
		t.Error("expected FileDefaultAllow=false")
	}
	if !plan.Config.NetDefaultAllow {
		t.Error("expected NetDefaultAllow=true")
	}
	if plan.CgroupID != 42 {
		t.Errorf("expected CgroupID=42, got %d", plan.CgroupID)
	}
}

func TestBuildPlan_RejectsNilPolicy(t *testing.T) {
	if _, _, err := BuildPlan(1, nil, 0); err == nil {
		t.Fatal("expected error for nil policy")
	}
}

func TestBuildPlan_ExecRulesUseCorrectHashesAndOrder(t *testing.T) {
	p := minimalPolicy()
	p.Spec.Exec.AllowedPaths = []string{"/bin/bash"}
	p.Spec.Exec.DeniedPaths = []string{"/usr/bin/curl"}

	plan, _, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.ExecRules) != 2 {
		t.Fatalf("expected 2 exec rules, got %d", len(plan.ExecRules))
	}
	// Denied paths are translated first, then allowed — see doc comment: the
	// loader writes deny entries last so they win on a duplicate key, so
	// BuildPlan's ordering here (deny before allow) determines final map
	// state when the same path appears in both lists.
	if plan.ExecRules[0].Path != "/usr/bin/curl" || plan.ExecRules[0].Allow {
		t.Errorf("expected first rule to be deny /usr/bin/curl, got %+v", plan.ExecRules[0])
	}
	if plan.ExecRules[1].Path != "/bin/bash" || !plan.ExecRules[1].Allow {
		t.Errorf("expected second rule to be allow /bin/bash, got %+v", plan.ExecRules[1])
	}
	if plan.ExecRules[1].PathHash != pathhash.Hash("/bin/bash") {
		t.Error("expected PathHash to match pathhash.Hash exactly (cross-language contract)")
	}
}

func TestBuildPlan_FileRulesCombineFileAndDevicePolicies(t *testing.T) {
	p := minimalPolicy()
	p.Spec.FileAccess.AllowedPathPrefixes = []string{"/models/weights.bin"}
	p.Spec.DeviceAccess.AllowedDevicePaths = []string{"/dev/nvidia0"}
	p.Spec.FileAccess.DeniedPathPrefixes = []string{"/etc/shadow"}

	plan, _, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.FileRules) != 3 {
		t.Fatalf("expected 3 file rules (file+device+denied combined), got %d", len(plan.FileRules))
	}
	var sawDevice, sawFile, sawDenied bool
	for _, r := range plan.FileRules {
		switch r.Path {
		case "/dev/nvidia0":
			sawDevice = r.Allow
		case "/models/weights.bin":
			sawFile = r.Allow
		case "/etc/shadow":
			sawDenied = !r.Allow
		}
	}
	if !sawDevice || !sawFile || !sawDenied {
		t.Errorf("expected all three rules present with correct actions, got %+v", plan.FileRules)
	}
}

func TestBuildPlan_DeviceRulesUseFileHookMap(t *testing.T) {
	p := minimalPolicy()
	p.Spec.DeviceAccess.DefaultAction = "allow"
	p.Spec.DeviceAccess.AllowedDevicePaths = []string{"/dev/nvidia0"}

	plan, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped CIDRs, got %+v", skipped)
	}
	if !plan.Config.DeviceDefaultAllow {
		t.Error("expected DeviceDefaultAllow=true")
	}
	if len(plan.FileRules) != 1 {
		t.Fatalf("expected 1 device path rule in file_rules, got %d", len(plan.FileRules))
	}
	r := plan.FileRules[0]
	if r.Path != "/dev/nvidia0" || !r.Allow {
		t.Fatalf("expected allow rule for /dev/nvidia0 in file_rules, got %+v", r)
	}
	if r.PathHash != pathhash.Hash("/dev/nvidia0") {
		t.Error("expected device path hash to match pathhash.Hash exactly")
	}
}

func TestBuildPlan_NetCIDR_SingleHostNoPorts(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.AllowedCIDRs = []string{"10.0.0.1/32"}

	plan, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped CIDRs, got %+v", skipped)
	}
	if len(plan.NetRules) != 1 {
		t.Fatalf("expected 1 net rule, got %d", len(plan.NetRules))
	}
	r := plan.NetRules[0]
	if r.DestPort != 0 {
		t.Errorf("expected port wildcard (0) when AllowedPorts is empty, got %d", r.DestPort)
	}
	if !r.Allow {
		t.Error("expected allow=true")
	}
	// 10.0.0.1 raw s_addr, cross-verified against a compiled C reference
	// using inet_pton + struct sockaddr_in (see EXPERIMENTS_LOG.md Phase 4).
	const want = 0x0100000a
	if r.DestAddrV4 != want {
		t.Errorf("DestAddrV4 = 0x%08x, want 0x%08x (C-verified raw s_addr for 10.0.0.1)", r.DestAddrV4, want)
	}
}

func TestBuildPlan_NetCIDR_BareIPTreatedAsSlash32(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.AllowedCIDRs = []string{"1.2.3.4"}

	plan, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped CIDRs for a bare IP, got %+v", skipped)
	}
	if len(plan.NetRules) != 1 {
		t.Fatalf("expected 1 net rule, got %d", len(plan.NetRules))
	}
	// 1.2.3.4 raw s_addr, cross-verified against the same compiled C reference.
	const want = 0x04030201
	if plan.NetRules[0].DestAddrV4 != want {
		t.Errorf("DestAddrV4 = 0x%08x, want 0x%08x (C-verified raw s_addr for 1.2.3.4)", plan.NetRules[0].DestAddrV4, want)
	}
}

func TestBuildPlan_NetCIDR_WithExplicitPorts(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.AllowedCIDRs = []string{"10.0.0.1/32"}
	p.Spec.NetworkEgress.AllowedPorts = []int32{443, 8443}

	plan, _, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.NetRules) != 2 {
		t.Fatalf("expected 2 net rules (one per port), got %d", len(plan.NetRules))
	}
	ports := map[uint16]bool{}
	for _, r := range plan.NetRules {
		ports[r.DestPort] = true
	}
	if !ports[443] || !ports[8443] {
		t.Errorf("expected rules for ports 443 and 8443, got %+v", plan.NetRules)
	}
}

func TestBuildPlan_NetDeniedCIDRProducesDenyRule(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.DeniedCIDRs = []string{"10.0.0.9/32"}

	plan, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(skipped) != 0 {
		t.Fatalf("expected no skipped CIDRs, got %+v", skipped)
	}
	if len(plan.NetRules) != 1 {
		t.Fatalf("expected 1 denied net rule, got %d", len(plan.NetRules))
	}
	r := plan.NetRules[0]
	if r.Allow {
		t.Error("expected allow=false for deniedCIDRs rule")
	}
	if r.DestPort != 0 {
		t.Errorf("expected deniedCIDRs rule to use port wildcard (0), got %d", r.DestPort)
	}
	const want = 0x0900000a
	if r.DestAddrV4 != want {
		t.Errorf("DestAddrV4 = 0x%08x, want 0x%08x (raw s_addr for 10.0.0.9)", r.DestAddrV4, want)
	}
}

func TestBuildPlan_SkipsCIDRBroaderThanSlash32(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.AllowedCIDRs = []string{"10.0.0.0/24"}

	plan, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(plan.NetRules) != 0 {
		t.Fatalf("expected no net rules generated for an unsupported CIDR range, got %+v", plan.NetRules)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected exactly 1 skipped CIDR to be reported, got %+v", skipped)
	}
	if skipped[0].CIDR != "10.0.0.0/24" || skipped[0].Policy != "allowedCIDRs" {
		t.Errorf("unexpected skipped entry: %+v", skipped[0])
	}
}

func TestBuildPlan_RejectsMalformedCIDR(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.AllowedCIDRs = []string{"not-an-ip-or-cidr"}

	_, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan should not itself error on a bad entry (reported via skipped instead): %v", err)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected the malformed entry to be reported as skipped, got %+v", skipped)
	}
}

func TestBuildPlan_RejectsIPv6(t *testing.T) {
	p := minimalPolicy()
	p.Spec.NetworkEgress.AllowedCIDRs = []string{"::1/128"}

	_, skipped, err := BuildPlan(1, p, 0)
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if len(skipped) != 1 {
		t.Fatalf("expected IPv6 entry to be reported as skipped (documented limitation), got %+v", skipped)
	}
}
