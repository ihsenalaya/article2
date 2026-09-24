// Package lsmdetect determines whether BPF-LSM ("bpf" in the active LSM
// chain) is actually active on this node, not merely compiled into the
// kernel. This distinction matters: Phase 0 of this project found a real
// kernel (this dev machine's WSL2 host) where CONFIG_BPF_LSM=y but "bpf" is
// absent from /sys/kernel/security/lsm — meaning the enforce-capable
// lsm/* programs in bpf/agent.bpf.c cannot be attached, and the agent must
// fall back to the audit-only tracepoint programs. Phase 9 requires the same
// check as a pre-flight gate on real AKS nodes, since it is not guaranteed
// there either.
package lsmdetect

import (
	"os"
	"strings"
)

// DefaultLSMPath is the standard securityfs location for the active LSM list.
const DefaultLSMPath = "/sys/kernel/security/lsm"

// BPFLSMActive reports whether "bpf" appears in the comma-separated active
// LSM list at path. A missing file (securityfs not mounted, or the path
// simply not existing) is treated as "not active" rather than an error: from
// the caller's perspective both cases mean the same thing — fall back to
// audit-only mode — and Phase 0 already found securityfs unmounted by
// default on this dev kernel, which is itself a legitimate real-world case
// this function must handle without erroring.
func BPFLSMActive(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	for _, lsm := range strings.Split(strings.TrimSpace(string(data)), ",") {
		if strings.TrimSpace(lsm) == "bpf" {
			return true
		}
	}
	return false
}

// Mode identifies which family of eBPF programs (bpf/agent.bpf.c) the agent
// should attach.
type Mode string

const (
	// ModeAudit attaches the tracepoint programs: observation only, never blocks.
	ModeAudit Mode = "audit"
	// ModeEnforce attaches the LSM programs: can actually deny.
	ModeEnforce Mode = "enforce"
)

// DetermineMode returns ModeEnforce only when BPF-LSM is actually active;
// otherwise it returns ModeAudit, regardless of what the caller might prefer
// (there is no way to enforce without BPF-LSM — tracepoints cannot deny).
func DetermineMode(lsmPath string) Mode {
	if BPFLSMActive(lsmPath) {
		return ModeEnforce
	}
	return ModeAudit
}
