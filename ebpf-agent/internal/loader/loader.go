// Package loader wires the generated BPF objects (internal/bpfobjs) to the
// kernel: attaching the correct program family for the node's detected mode
// (internal/lsmdetect), writing policy maps (internal/policy's pure Plan
// output), and reading back the ring buffer of observed events.
//
// This package needs real kernel privileges (CAP_BPF/CAP_SYS_ADMIN or root)
// to do anything at all, which this project's unprivileged dev-machine user
// does not have — so unlike cgroupmap/pathhash/lsmdetect/policy/evidence, it
// is not unit-tested here. It gets exercised for real once the agent runs as
// a privileged container in kind (Phase 5). The design keeps every piece
// that *can* be tested without kernel access (hashing, mapping, translation,
// signing) in separate, already-tested packages this one just calls into.
package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/bpfobjs"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/lsmdetect"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/policy"
)

// auditPrograms/enforcePrograms are deliberately narrower than the full
// bpfobjs.AgentPrograms: loading (and thus kernel-verifying) a program
// happens for every entry present in a CollectionSpec when the Collection is
// built, regardless of which struct fields the caller later reads — using
// the full generated AgentObjects unconditionally would load, and verify,
// the enforce-capable lsm/* programs even on a node running in audit mode,
// where they will never be attached. Pruning the CollectionSpec down to only
// the programs the active mode needs (see Load, below) avoids that
// unnecessary — and on some kernels possibly failing — verification.
type auditPrograms struct {
	bpfobjs.AgentMaps
	TraceExecve  *ebpf.Program `ebpf:"trace_execve"`
	TraceOpen    *ebpf.Program `ebpf:"trace_open"`
	TraceOpenat  *ebpf.Program `ebpf:"trace_openat"`
	TraceConnect *ebpf.Program `ebpf:"trace_connect"`
}

type enforcePrograms struct {
	bpfobjs.AgentMaps
	LsmExec     *ebpf.Program `ebpf:"lsm_exec"`
	LsmFileOpen *ebpf.Program `ebpf:"lsm_file_open"`
	LsmConnect  *ebpf.Program `ebpf:"lsm_connect"`
	LsmBpfLock  *ebpf.Program `ebpf:"lsm_bpf_lock"`
}

// Agent owns the loaded BPF objects and their kernel attachments for the
// node's lifetime. Only the program fields relevant to mode are ever
// non-nil; maps are always all loaded (every mode needs them).
type Agent struct {
	mode lsmdetect.Mode
	maps bpfobjs.AgentMaps

	traceExecve, traceOpen, traceOpenat, traceConnect *ebpf.Program
	lsmExec, lsmFileOpen, lsmConnect, lsmBpfLock      *ebpf.Program

	links []link.Link

	// lsmExecLink/lsmFileOpenLink/lsmConnectLink are BENCHMARK-ONLY (see
	// common.h's BENCH_MODE_* doc comment): kept as named fields, separate
	// from the generic links slice above, so DetachHook/ReattachHook can
	// close/reopen exactly one hook's kernel attachment without touching the
	// other two. nil whenever mode != ModeEnforce or the hook is currently
	// detached. Never used in production (--benchmark-mode-enabled is false
	// by default).
	lsmExecLink, lsmFileOpenLink, lsmConnectLink link.Link
}

// allProgramNames lists every program name bpf2go generated (see
// bpfobjs.AgentProg* constants) — used to compute which ones to prune per mode.
var auditProgramNames = []string{
	bpfobjs.AgentProgTraceExecve,
	bpfobjs.AgentProgTraceOpen,
	bpfobjs.AgentProgTraceOpenat,
	bpfobjs.AgentProgTraceConnect,
}

var enforceProgramNames = []string{
	bpfobjs.AgentProgLsmExec,
	bpfobjs.AgentProgLsmFileOpen,
	bpfobjs.AgentProgLsmConnect,
	bpfobjs.AgentProgLsmBpfLock,
}

// Load loads the compiled BPF collection and attaches the program family
// appropriate for mode: tracepoints (audit, observation-only) or LSM hooks
// (enforce, can actually deny). Never both — see agent.bpf.c's doc comment.
func Load(mode lsmdetect.Mode) (*Agent, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}

	spec, err := bpfobjs.LoadAgent()
	if err != nil {
		return nil, fmt.Errorf("load BPF collection spec: %w", err)
	}

	a := &Agent{mode: mode}
	// LogSize/LogLevel are raised from cilium/ebpf's defaults (which return
	// only a short truncated tail on a verifier rejection) so a load failure
	// during development yields a full, actionable verifier log instead of
	// "(N line(s) omitted)". Harmless in production: this only affects the
	// log captured when a load fails, not runtime behavior on success.
	opts := &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction, LogSizeStart: 4 * 1024 * 1024},
	}

	if mode == lsmdetect.ModeEnforce {
		pruneProgramSpecs(spec, auditProgramNames)
		var o enforcePrograms
		if err := spec.LoadAndAssign(&o, opts); err != nil {
			return nil, fmt.Errorf("load enforce-mode BPF objects: %w", err)
		}
		a.maps = o.AgentMaps
		a.lsmExec, a.lsmFileOpen, a.lsmConnect, a.lsmBpfLock = o.LsmExec, o.LsmFileOpen, o.LsmConnect, o.LsmBpfLock
		if err := a.attachEnforce(); err != nil {
			a.Close()
			return nil, err
		}
	} else {
		pruneProgramSpecs(spec, enforceProgramNames)
		var o auditPrograms
		if err := spec.LoadAndAssign(&o, opts); err != nil {
			return nil, fmt.Errorf("load audit-mode BPF objects: %w", err)
		}
		a.maps = o.AgentMaps
		a.traceExecve, a.traceOpen, a.traceOpenat, a.traceConnect = o.TraceExecve, o.TraceOpen, o.TraceOpenat, o.TraceConnect
		if err := a.attachAudit(); err != nil {
			a.Close()
			return nil, err
		}
	}

	return a, nil
}

func pruneProgramSpecs(spec *ebpf.CollectionSpec, names []string) {
	for _, name := range names {
		delete(spec.Programs, name)
	}
}

func (a *Agent) attachAudit() error {
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", a.traceExecve, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_execve: %w", err)
	}
	a.links = append(a.links, tp)

	// Both open(2) and openat(2) must be hooked — see handle_file_open's doc
	// comment in agent.bpf.c for why relying on only one silently misses
	// real file accesses depending on which syscall the caller happens to use.
	tp, err = link.Tracepoint("syscalls", "sys_enter_open", a.traceOpen, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_open: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_openat", a.traceOpenat, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_openat: %w", err)
	}
	a.links = append(a.links, tp)

	tp, err = link.Tracepoint("syscalls", "sys_enter_connect", a.traceConnect, nil)
	if err != nil {
		return fmt.Errorf("attach tracepoint sys_enter_connect: %w", err)
	}
	a.links = append(a.links, tp)
	return nil
}

func (a *Agent) attachEnforce() error {
	l, err := link.AttachLSM(link.LSMOptions{Program: a.lsmExec})
	if err != nil {
		return fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}
	a.lsmExecLink = l

	l, err = link.AttachLSM(link.LSMOptions{Program: a.lsmFileOpen})
	if err != nil {
		return fmt.Errorf("attach lsm/file_open: %w", err)
	}
	a.lsmFileOpenLink = l

	l, err = link.AttachLSM(link.LSMOptions{Program: a.lsmConnect})
	if err != nil {
		return fmt.Errorf("attach lsm/socket_connect: %w", err)
	}
	a.lsmConnectLink = l
	return nil
}

// hookLink returns a pointer to the named hook's link field, so
// DetachHook/ReattachHook can share one implementation instead of
// duplicating the switch three times. BENCHMARK-ONLY, see the doc comment
// on the lsmExecLink/lsmFileOpenLink/lsmConnectLink fields.
func (a *Agent) hookLink(name string) (*link.Link, *ebpf.Program, error) {
	switch name {
	case "exec":
		return &a.lsmExecLink, a.lsmExec, nil
	case "file":
		return &a.lsmFileOpenLink, a.lsmFileOpen, nil
	case "connect":
		return &a.lsmConnectLink, a.lsmConnect, nil
	default:
		return nil, nil, fmt.Errorf("unknown benchmark hook %q (want exec, file, or connect)", name)
	}
}

// DetachHook closes exactly one LSM hook's kernel attachment (the already-
// loaded program itself stays loaded; only the link is closed), leaving the
// other two hooks untouched. BENCHMARK-ONLY (see common.h's BENCH_MODE_* doc
// comment) -- exists solely for
// artifacts/bpf_lsm_enforcement_overhead's C0 condition (BPF-LSM genuinely
// not attached for the operation under test), driven only by the opt-in
// benchmark control poller in cmd/agent (--benchmark-mode-enabled). A no-op
// if the hook is already detached.
func (a *Agent) DetachHook(name string) error {
	if a.mode != lsmdetect.ModeEnforce {
		return fmt.Errorf("DetachHook requires enforce mode (mode=%s)", a.mode)
	}
	field, _, err := a.hookLink(name)
	if err != nil {
		return err
	}
	if *field == nil {
		return nil
	}
	if err := (*field).Close(); err != nil {
		return fmt.Errorf("detach %s hook: %w", name, err)
	}
	*field = nil
	return nil
}

// ReattachHook re-opens a link for the named hook's already-loaded program
// (no reload). BENCHMARK-ONLY, see DetachHook's doc comment. A no-op if
// already attached.
func (a *Agent) ReattachHook(name string) error {
	if a.mode != lsmdetect.ModeEnforce {
		return fmt.Errorf("ReattachHook requires enforce mode (mode=%s)", a.mode)
	}
	field, prog, err := a.hookLink(name)
	if err != nil {
		return err
	}
	if *field != nil {
		return nil
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: prog})
	if err != nil {
		return fmt.Errorf("reattach %s hook: %w", name, err)
	}
	*field = l
	return nil
}

// SetBenchmarkMode overwrites just the benchmark_mode byte of an existing
// cgroup_configs entry (read-modify-write), leaving every other field
// (enforcement mode, default-allow flags) untouched. The entry must already
// exist via a prior ApplyPlan -- this never creates one. BENCHMARK-ONLY, see
// common.h's BENCH_MODE_* doc comment.
func (a *Agent) SetBenchmarkMode(cgroupID uint64, mode uint8) error {
	var cfg bpfobjs.AgentCgroupConfig
	if err := a.maps.CgroupConfigs.Lookup(&cgroupID, &cfg); err != nil {
		return fmt.Errorf("lookup cgroup_configs[%d]: %w", cgroupID, err)
	}
	cfg.BenchmarkMode = mode
	if err := a.maps.CgroupConfigs.Put(&cgroupID, &cfg); err != nil {
		return fmt.Errorf("write cgroup_configs[%d] benchmark_mode: %w", cgroupID, err)
	}
	return nil
}

// EnableBPFLock attaches the BPF-lock LSM hook and flips its "engaged" flag,
// so from this point on the node denies further bpf(2) program loads. Only
// meaningful (and only called) when mode is ModeEnforce and
// RuntimeSecurityPolicy.Spec.BPFLock.Enabled is true — see Phase 4's
// "defense in depth" requirement and its documented conflict risk with other
// node eBPF tooling (CNI, observability), which is exactly why this is an
// explicit opt-in call, not automatic.
func (a *Agent) EnableBPFLock() error {
	if a.mode != lsmdetect.ModeEnforce {
		return fmt.Errorf("BPF-lock requires BPF-LSM to be active (mode=%s)", a.mode)
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: a.lsmBpfLock})
	if err != nil {
		return fmt.Errorf("attach lsm/bpf: %w", err)
	}
	a.links = append(a.links, l)

	var key uint32
	engaged := uint32(1)
	if err := a.maps.BpfLockEngaged.Put(&key, &engaged); err != nil {
		return fmt.Errorf("engage bpf_lock_engaged flag: %w", err)
	}
	return nil
}

// ApplyPlan writes plan's cgroup_config and rule entries into the kernel
// maps. Rules are written allow-entries-then-deny-entries in plan's own
// slice order (see policy.BuildPlan's doc comment on why deny should win on
// a duplicate key) — Put() naturally overwrites on a repeated key, so
// writing in that order is sufficient, no special-casing needed here.
func (a *Agent) ApplyPlan(plan *policy.Plan) error {
	cfg := bpfobjs.AgentCgroupConfig{
		EnforcementMode:    plan.Config.EnforcementMode,
		ExecDefaultAllow:   boolToU8(plan.Config.ExecDefaultAllow),
		FileDefaultAllow:   boolToU8(plan.Config.FileDefaultAllow),
		NetDefaultAllow:    boolToU8(plan.Config.NetDefaultAllow),
		DeviceDefaultAllow: boolToU8(plan.Config.DeviceDefaultAllow),
	}
	// BENCHMARK-ONLY (see common.h's BENCH_MODE_* doc comment): preserve
	// whatever benchmark_mode SetBenchmarkMode most recently set for this
	// cgroup, rather than always resetting it to 0. Without this, the
	// regular poll-loop's routine reconciliation (every --poll-interval,
	// unconditional for every tracked policy) would race with and silently
	// undo artifacts/bpf_lsm_enforcement_overhead's own control channel --
	// caught concretely during that experiment's development (intermittent
	// C1/C2 measurements silently reverting to production mode mid-block).
	// A no-op for every normal deployment: benchmark_mode is only ever
	// non-zero on the one cgroup the opt-in benchmark orchestration targets.
	var existing bpfobjs.AgentCgroupConfig
	if err := a.maps.CgroupConfigs.Lookup(&plan.CgroupID, &existing); err == nil {
		cfg.BenchmarkMode = existing.BenchmarkMode
	}
	if err := a.maps.CgroupConfigs.Put(&plan.CgroupID, &cfg); err != nil {
		return fmt.Errorf("write cgroup_configs[%d]: %w", plan.CgroupID, err)
	}

	for _, r := range plan.ExecRules {
		key := bpfobjs.AgentPathRuleKey{CgroupId: plan.CgroupID, PathHash: r.PathHash}
		val := bpfobjs.AgentRuleAction{Allow: boolToU8(r.Allow)}
		if err := a.maps.ExecRules.Put(&key, &val); err != nil {
			return fmt.Errorf("write exec_rules[%d,%q]: %w", plan.CgroupID, r.Path, err)
		}
	}
	for _, r := range plan.FileRules {
		key := bpfobjs.AgentPathRuleKey{CgroupId: plan.CgroupID, PathHash: r.PathHash}
		val := bpfobjs.AgentRuleAction{Allow: boolToU8(r.Allow)}
		if err := a.maps.FileRules.Put(&key, &val); err != nil {
			return fmt.Errorf("write file_rules[%d,%q]: %w", plan.CgroupID, r.Path, err)
		}
	}
	for _, r := range plan.NetRules {
		key := bpfobjs.AgentNetRuleKey{CgroupId: plan.CgroupID, DestAddrV4: r.DestAddrV4, DestPort: r.DestPort}
		val := bpfobjs.AgentRuleAction{Allow: boolToU8(r.Allow)}
		if err := a.maps.NetRules.Put(&key, &val); err != nil {
			return fmt.Errorf("write net_rules[%d,%q]: %w", plan.CgroupID, r.CIDR, err)
		}
	}
	return nil
}

// RevokeCgroup retracts access for cgroupID: it does NOT delete the
// cgroup_configs entry (see agent.bpf.c's doc comment on get_cgroup_config —
// a missing entry means "allow" in the LSM hooks, the opposite of
// revocation). Instead it overwrites the entry with a deny-by-default
// config (the zero value of AgentCgroupConfig is exactly "deny everything",
// since boolToU8(false)==0) and deletes every exec/file/net rule for this
// cgroup, so no stale ALLOW entry can override the new default-deny.
func (a *Agent) RevokeCgroup(cgroupID uint64) error {
	deny := bpfobjs.AgentCgroupConfig{EnforcementMode: uint8(lsmDetectModeValue(a.mode))}
	if err := a.maps.CgroupConfigs.Put(&cgroupID, &deny); err != nil {
		return fmt.Errorf("revoke cgroup_configs[%d]: %w", cgroupID, err)
	}

	if err := deleteMatchingCgroup(a.maps.ExecRules, cgroupID); err != nil {
		return fmt.Errorf("clear exec_rules for cgroup %d: %w", cgroupID, err)
	}
	if err := deleteMatchingCgroup(a.maps.FileRules, cgroupID); err != nil {
		return fmt.Errorf("clear file_rules for cgroup %d: %w", cgroupID, err)
	}
	if err := deleteMatchingNetCgroup(a.maps.NetRules, cgroupID); err != nil {
		return fmt.Errorf("clear net_rules for cgroup %d: %w", cgroupID, err)
	}
	return nil
}

func deleteMatchingCgroup(m *ebpf.Map, cgroupID uint64) error {
	var key bpfobjs.AgentPathRuleKey
	var val bpfobjs.AgentRuleAction
	var toDelete []bpfobjs.AgentPathRuleKey
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if key.CgroupId == cgroupID {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range toDelete {
		k := k
		if err := m.Delete(&k); err != nil {
			return err
		}
	}
	return nil
}

func deleteMatchingNetCgroup(m *ebpf.Map, cgroupID uint64) error {
	var key bpfobjs.AgentNetRuleKey
	var val bpfobjs.AgentRuleAction
	var toDelete []bpfobjs.AgentNetRuleKey
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		if key.CgroupId == cgroupID {
			toDelete = append(toDelete, key)
		}
	}
	if err := iter.Err(); err != nil {
		return err
	}
	for _, k := range toDelete {
		k := k
		if err := m.Delete(&k); err != nil {
			return err
		}
	}
	return nil
}

func lsmDetectModeValue(m lsmdetect.Mode) int {
	if m == lsmdetect.ModeEnforce {
		return 1
	}
	return 0
}

func boolToU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// EventCounters is the node-wide, cumulative event-loss accounting (Task 05,
// B1): Generated == Emitted + Dropped by construction (see agent.bpf.c
// emit_event / common.h's COUNTER_* doc comment).
type EventCounters struct {
	Generated uint64
	Emitted   uint64
	Dropped   uint64
	// LSMHookEntered (Task 10 follow-up, COUNTER_LSM_HOOK_ENTERED): bumped
	// unconditionally as the first instruction of every lsm/* program, before
	// any cfg lookup or decision logic. Only meaningful in enforce mode
	// (audit-mode's tracepoint programs never touch this counter). Lets a
	// live diagnostic distinguish "the kernel never invoked the hook for this
	// syscall" from "the hook ran and returned -1 but the kernel didn't
	// enforce it" -- neither prior ground-truth check (bpftool map dump of
	// policy config, bpftool prog dump xlated of the bytecode) could tell
	// these apart. See artifacts/experiments/bpf-lsm/exclusions.md.
	LSMHookEntered uint64
}

// ReadEventCounters sums the event_counters PERCPU_ARRAY map across all CPUs.
// Indices below must match common.h's COUNTER_GENERATED/EMITTED/DROPPED/
// LSM_HOOK_ENTERED (plain #define macros, so bpf2go does not generate Go
// constants for them).
func (a *Agent) ReadEventCounters() (EventCounters, error) {
	var out EventCounters
	for idx, dst := range map[uint32]*uint64{
		0: &out.Generated,
		1: &out.Emitted,
		2: &out.Dropped,
		3: &out.LSMHookEntered,
	} {
		var perCPU []uint64
		if err := a.maps.EventCounters.Lookup(idx, &perCPU); err != nil {
			return EventCounters{}, fmt.Errorf("read event_counters[%d]: %w", idx, err)
		}
		var sum uint64
		for _, v := range perCPU {
			sum += v
		}
		*dst = sum
	}
	return out, nil
}

// ReadEvents blocks reading ring buffer records and invokes handler for each
// decoded event, until the reader is closed (via Close) or a read error
// occurs. Intended to run in its own goroutine.
func (a *Agent) ReadEvents(handler func(bpfobjs.AgentEvent)) error {
	reader, err := ringbuf.NewReader(a.maps.Events)
	if err != nil {
		return fmt.Errorf("open ringbuf reader: %w", err)
	}
	defer reader.Close()

	for {
		record, err := reader.Read()
		if err != nil {
			if err == ringbuf.ErrClosed {
				return nil
			}
			return fmt.Errorf("read ringbuf record: %w", err)
		}
		var event bpfobjs.AgentEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			return fmt.Errorf("decode ringbuf record: %w", err)
		}
		handler(event)
	}
}

// Close detaches all links and closes the BPF maps/programs.
func (a *Agent) Close() error {
	for _, l := range a.links {
		_ = l.Close()
	}
	for _, l := range []link.Link{a.lsmExecLink, a.lsmFileOpenLink, a.lsmConnectLink} {
		if l != nil {
			_ = l.Close()
		}
	}
	closers := []ebpfCloser{&a.maps}
	for _, p := range []*ebpf.Program{a.traceExecve, a.traceOpenat, a.traceConnect, a.lsmExec, a.lsmFileOpen, a.lsmConnect, a.lsmBpfLock} {
		if p != nil {
			closers = append(closers, p)
		}
	}
	var firstErr error
	for _, c := range closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

type ebpfCloser interface {
	Close() error
}
