/* SPDX-License-Identifier: GPL-2.0
 *
 * Shared type definitions between the eBPF programs (agent.bpf.c) and the Go
 * userspace loader. Kept in a header of its own (rather than inline in
 * agent.bpf.c) so bpf2go's Go type generation and any future additional .bpf.c
 * source files see identical layouts.
 *
 * Design notes (see DESIGN.md / EXPERIMENTS_LOG.md Phase 4 for the reasoning):
 *
 *  - Path matching is exact-hash, not prefix/glob. The eBPF verifier does not
 *    allow unbounded string scanning, so allowed/denied paths are hashed
 *    (FNV-1a over a bounded MAX_PATH_LEN buffer) both here and in the Go
 *    loader when it populates exec_rules/file_rules from a
 *    RuntimeSecurityPolicy's AllowedPaths/AllowedPathPrefixes. This means
 *    "prefix" fields in the CRD are currently expanded to individual exact
 *    paths by the loader, not evaluated as true prefixes in-kernel — a
 *    documented limitation, not an oversight.
 *  - Network egress matching is exact (cgroup_id, dest_ipv4, dest_port).
 *    IPv6 and CIDR-range matching are out of scope for this phase (documented
 *    limitation) — a real implementation would use BPF_MAP_TYPE_LPM_TRIE for
 *    CIDR ranges; deferred to keep the policy matching architecture uniform
 *    (single hash-map-keyed-by-cgroup pattern) across all four hook types
 *    within the time available for this phase.
 *  - Tracepoint programs (audit-only path, used when BPF-LSM is not active in
 *    the active LSM chain — this dev machine's WSL2 kernel today) can only
 *    observe: a tracepoint's return value does not influence the syscall
 *    outcome, so "decision" on events from tracepoint programs is always
 *    "what would have happened", never an actual block. Only the lsm-prefixed
 *    programs (used when BPF-LSM is active) can actually deny.
 */
#ifndef RUNTIME_GUARD_COMMON_H
#define RUNTIME_GUARD_COMMON_H

/* AF_INET is a libc/userspace sockaddr.h constant, not a kernel BTF type, so
 * it is not in vmlinux.h — BPF C programs conventionally define the handful
 * of socket-family constants they need directly, rather than pulling in
 * userspace headers that are not valid in this compilation target. */
#define AF_INET 2

#define MAX_PATH_LEN 256

/* event.type */
#define EVENT_TYPE_EXEC        1
#define EVENT_TYPE_FILE_OPEN   2
#define EVENT_TYPE_CONNECT     3
#define EVENT_TYPE_DEVICE_OPEN 4
#define EVENT_TYPE_BPF_LOAD_BLOCKED 5

/* event.decision */
#define DECISION_ALLOWED         0
#define DECISION_DENIED          1
#define DECISION_AUDIT_WOULD_DENY 2 /* audit-only mode: would have been denied, but not enforced */

/* event.hook_mode */
#define HOOK_MODE_AUDIT   0 /* tracepoint-backed, observation only */
#define HOOK_MODE_ENFORCE 1 /* LSM-backed, can actually deny */

/* event_counters map indices (Task 05, Experiment B1 -- event-loss
 * accounting). GENERATED is bumped every time a hook decides to emit an
 * event (before attempting bpf_ringbuf_reserve); EMITTED is bumped only on
 * a successful reserve+submit; DROPPED is bumped when bpf_ringbuf_reserve
 * fails (ring buffer full) -- this is the exact silent-loss path Task 00's
 * audit found had NO accounting at all. GENERATED == EMITTED + DROPPED by
 * construction; userspace sums these (they are BPF_MAP_TYPE_PERCPU_ARRAY)
 * across CPUs to get node-wide totals. A dropped event's cgroup_id is
 * unknowable by construction (the reservation that would carry it never
 * succeeded), so this accounting is deliberately node-wide, not
 * per-cgroup -- see artifacts/experiments/observation-completeness/. */
#define COUNTER_GENERATED  0
#define COUNTER_EMITTED    1
#define COUNTER_DROPPED    2
/* LSM_HOOK_ENTERED (Task 10 follow-up): bumped as the FIRST instruction of
 * every lsm/* program, before any cfg lookup or decision logic -- the sole
 * purpose is to distinguish "the kernel never invoked this hook for the
 * attempted operation" from "the hook ran and computed a decision that the
 * kernel then failed to enforce." G1's DENY reps never observed EPERM
 * despite independently-confirmed-correct kernel-side policy configuration
 * (bpftool map dump) and correct compiled bytecode (bpftool prog dump
 * xlated); neither check could tell whether the hook was even called for
 * those specific syscalls. This counter answers that directly. See
 * artifacts/experiments/bpf-lsm/exclusions.md. */
#define COUNTER_LSM_HOOK_ENTERED 3
#define NUM_EVENT_COUNTERS 4

struct event {
	__u64 cgroup_id;
	__u64 timestamp_ns;
	__u32 pid;
	__u32 tgid;
	__u8 type;
	__u8 decision;
	__u8 hook_mode;
	__u8 _pad0;
	__u32 dest_addr_v4; /* network byte order; only meaningful for EVENT_TYPE_CONNECT */
	__u16 dest_port;    /* host byte order; only meaningful for EVENT_TYPE_CONNECT */
	__u8 _pad1[2];
	char path[MAX_PATH_LEN]; /* exec path / opened path; empty for CONNECT events */
};

/* BENCHMARK-ONLY (reviewer-requested BPF-LSM enforcement-path microbenchmark,
 * artifacts/bpf_lsm_enforcement_overhead/). Not a production feature: every
 * existing caller of ApplyPlan leaves this at its Go zero-value, so
 * production behavior (mode 0) is exactly today's code path, unchanged. Only
 * the benchmark's own orchestration ever sets 1 or 2, and only on the one
 * dedicated benchmark pod's cgroup. */
#define BENCH_MODE_OFF       0 /* production: full lookup + emit_event() -- also serves as C3 */
#define BENCH_MODE_NOOP      1 /* C1: hook entry + cfg lookup only, immediate ALLOW */
#define BENCH_MODE_MAP_ONLY  2 /* C2: + real rule-map lookup, immediate ALLOW/DENY, no emit_event() */

/* Per-cgroup configuration: enforcement mode and default (deny-by-default)
 * action for each hook family, populated by the Go loader from the
 * cgroup's RuntimeSecurityPolicy. */
struct cgroup_config {
	__u8 enforcement_mode; /* HOOK_MODE_AUDIT or HOOK_MODE_ENFORCE */
	__u8 exec_default_allow;
	__u8 file_default_allow;
	__u8 net_default_allow;
	__u8 device_default_allow;
	__u8 benchmark_mode; /* BENCH_MODE_* -- see doc comment above */
	__u8 _pad[2];
};

/* Composite key for exec_rules / file_rules: exact-match hash of a path
 * within a specific cgroup. */
struct path_rule_key {
	__u64 cgroup_id;
	__u64 path_hash;
};

/* Composite key for net_rules: exact-match (dest IPv4, dest port) within a
 * specific cgroup. */
struct net_rule_key {
	__u64 cgroup_id;
	__u32 dest_addr_v4;
	__u16 dest_port;
	__u16 _pad;
};

/* rule value: 1 = allow, 0 = deny. A dedicated struct (rather than a bare u8)
 * leaves room to add a "reason code" later without changing the map's value
 * layout in a way that breaks already-generated Go bindings. */
struct rule_action {
	__u8 allow;
	__u8 _pad[7];
};

#endif /* RUNTIME_GUARD_COMMON_H */
