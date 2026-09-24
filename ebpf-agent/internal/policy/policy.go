// Package policy translates a RuntimeSecurityPolicy (article 2's own CRD,
// aiopsv1alpha1 — shared with the Operator, see go.mod's replace directive)
// into the set of BPF map entries needed to enforce/audit it for one
// cgroup. Building this translation is pure computation with no kernel I/O,
// so it is fully unit-testable; actually writing the result into the kernel
// maps is the loader's job (internal/loader), which does need real kernel
// privileges this dev machine's unprivileged user does not have — the split
// exists precisely so the part that *can* be tested here, is.
package policy

import (
	"fmt"
	"net"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"

	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/pathhash"
)

// CgroupConfig mirrors bpf/common.h's struct cgroup_config.
type CgroupConfig struct {
	EnforcementMode    uint8 // lsmdetect/common.h HOOK_MODE_AUDIT (0) or HOOK_MODE_ENFORCE (1)
	ExecDefaultAllow   bool
	FileDefaultAllow   bool
	NetDefaultAllow    bool
	DeviceDefaultAllow bool
}

// PathRule is one exec_rules/file_rules entry: an exact path hash and its
// allow/deny action, for a specific cgroup (the cgroup ID is carried
// alongside in Plan, not duplicated per rule, since a Plan is always for one
// cgroup at a time).
type PathRule struct {
	Path     string // kept for logging/debugging; PathHash is what actually gets written
	PathHash uint64
	Allow    bool
}

// NetRule is one net_rules entry. DestPort == 0 is the loader's "any port"
// wildcard (see resolve_net_decision in agent.bpf.c) — never a real
// connect() destination port.
type NetRule struct {
	CIDR       string // kept for logging/debugging
	DestAddrV4 uint32 // network byte order (matches struct in_addr.s_addr)
	DestPort   uint16
	Allow      bool
}

// Plan is the full, pure translation of a RuntimeSecurityPolicy for one
// cgroup.
type Plan struct {
	CgroupID  uint64
	Config    CgroupConfig
	ExecRules []PathRule
	FileRules []PathRule // covers plain files and /dev/* device paths — see agent.bpf.c doc comment
	NetRules  []NetRule
}

// SkippedCIDR records a CIDR entry that BuildPlan could not translate into an
// exact-match rule (broader than /32 — see the documented limitation in
// bpf/common.h: no BPF_MAP_TYPE_LPM_TRIE support yet). Callers should log
// these, not silently drop them, so an operator can see that a rule is not
// actually being enforced/audited rather than assuming it is.
type SkippedCIDR struct {
	Policy string // "allowedCIDRs" or "deniedCIDRs", for error context
	CIDR   string
	Reason string
}

// BuildPlan translates policy for cgroupID into a Plan. enforcementMode
// should come from lsmdetect.DetermineMode (0=audit, 1=enforce) — it is a
// node-wide fact, not something the policy itself decides, since a node
// without active BPF-LSM cannot enforce regardless of what the policy asks
// for (see cgroup_config's doc comment in agent.bpf.c and DESIGN.md).
func BuildPlan(cgroupID uint64, p *aiopsv1alpha1.RuntimeSecurityPolicy, enforcementMode uint8) (*Plan, []SkippedCIDR, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("policy must not be nil")
	}

	plan := &Plan{
		CgroupID: cgroupID,
		Config: CgroupConfig{
			EnforcementMode:    enforcementMode,
			ExecDefaultAllow:   p.Spec.Exec.DefaultAction == "allow",
			FileDefaultAllow:   p.Spec.FileAccess.DefaultAction == "allow",
			NetDefaultAllow:    p.Spec.NetworkEgress.DefaultAction == "allow",
			DeviceDefaultAllow: p.Spec.DeviceAccess.DefaultAction == "allow",
		},
	}

	for _, path := range p.Spec.Exec.DeniedPaths {
		plan.ExecRules = append(plan.ExecRules, pathRule(path, false))
	}
	for _, path := range p.Spec.Exec.AllowedPaths {
		plan.ExecRules = append(plan.ExecRules, pathRule(path, true))
	}

	// Denied entries are appended after allowed ones for exec (checked above)
	// but the loader writes deny entries to the map *last* so they win on
	// duplicate keys (a path both allowed and denied is a policy authoring
	// error, but "deny wins" is the safer of the two silent resolutions).
	// For file/device rules, apply the same allow-then-deny ordering,
	// combining FileAccessPolicy and DeviceAccessPolicy into the single
	// file_rules map agent.bpf.c's file_open/openat hooks both consult.
	for _, path := range p.Spec.FileAccess.AllowedPathPrefixes {
		plan.FileRules = append(plan.FileRules, pathRule(path, true))
	}
	for _, path := range p.Spec.DeviceAccess.AllowedDevicePaths {
		plan.FileRules = append(plan.FileRules, pathRule(path, true))
	}
	for _, path := range p.Spec.FileAccess.DeniedPathPrefixes {
		plan.FileRules = append(plan.FileRules, pathRule(path, false))
	}

	var skipped []SkippedCIDR
	for _, cidr := range p.Spec.NetworkEgress.AllowedCIDRs {
		rules, skip, err := netRulesForCIDR(cidr, p.Spec.NetworkEgress.AllowedPorts, true)
		if err != nil {
			skipped = append(skipped, SkippedCIDR{Policy: "allowedCIDRs", CIDR: cidr, Reason: err.Error()})
			continue
		}
		if skip {
			skipped = append(skipped, SkippedCIDR{Policy: "allowedCIDRs", CIDR: cidr, Reason: "broader than /32 — exact-match-only implementation, see bpf/common.h"})
			continue
		}
		plan.NetRules = append(plan.NetRules, rules...)
	}
	for _, cidr := range p.Spec.NetworkEgress.DeniedCIDRs {
		rules, skip, err := netRulesForCIDR(cidr, nil, false)
		if err != nil {
			skipped = append(skipped, SkippedCIDR{Policy: "deniedCIDRs", CIDR: cidr, Reason: err.Error()})
			continue
		}
		if skip {
			skipped = append(skipped, SkippedCIDR{Policy: "deniedCIDRs", CIDR: cidr, Reason: "broader than /32 — exact-match-only implementation, see bpf/common.h"})
			continue
		}
		plan.NetRules = append(plan.NetRules, rules...)
	}

	return plan, skipped, nil
}

func pathRule(path string, allow bool) PathRule {
	return PathRule{Path: path, PathHash: pathhash.Hash(path), Allow: allow}
}

// netRulesForCIDR expands one CIDR entry into exact-match NetRules. Only
// /32 (a single host) is currently supported — see Plan's doc comment.
// ports empty means "any port" (encoded as the DestPort==0 wildcard).
func netRulesForCIDR(cidr string, ports []int32, allow bool) (rules []NetRule, skip bool, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// Accept a bare IP address (no "/32" suffix) as shorthand for a /32.
		if parsed := net.ParseIP(cidr); parsed != nil {
			ip = parsed
			ipNet = &net.IPNet{IP: parsed, Mask: net.CIDRMask(32, 32)}
		} else {
			return nil, false, fmt.Errorf("parse CIDR/IP %q: %w", cidr, err)
		}
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones != 32 {
		return nil, true, nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, false, fmt.Errorf("%q is not an IPv4 address (IPv6 out of scope for this phase)", cidr)
	}
	addr := rawSAddr(v4)

	if len(ports) == 0 {
		return []NetRule{{CIDR: cidr, DestAddrV4: addr, DestPort: 0, Allow: allow}}, false, nil
	}
	for _, port := range ports {
		rules = append(rules, NetRule{CIDR: cidr, DestAddrV4: addr, DestPort: uint16(port), Allow: allow})
	}
	return rules, false, nil
}

// rawSAddr reproduces the exact numeric value agent.bpf.c uses as a map key:
// struct in_addr's s_addr field holds the IP's 4 bytes in network
// (big-endian) order, but agent.bpf.c never byte-swaps it (bpf_ntohl is only
// applied to the port, not the address) — it uses the raw bit pattern
// directly. On this project's little-endian target (x86_64/amd64), loading
// those 4 memory bytes into a u32 register reverses them arithmetically:
// IP 1.2.3.4 (bytes [1,2,3,4]) becomes the number 0x04030201, not 0x01020304.
// Verified against a compiled C reference (see EXPERIMENTS_LOG.md Phase 4) —
// this is exactly the kind of byte-order detail that is easy to get
// confidently wrong through reasoning alone.
func rawSAddr(ip net.IP) uint32 {
	return uint32(ip[3])<<24 | uint32(ip[2])<<16 | uint32(ip[1])<<8 | uint32(ip[0])
}
