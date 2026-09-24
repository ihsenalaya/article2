/* SPDX-License-Identifier: GPL-2.0
 *
 * Runtime Guard eBPF agent — CO-RE program observing (and, when BPF-LSM is
 * active, enforcing) execve / file_open / connect / device-open behavior per
 * pod cgroup, against policy maps populated by the Go userspace loader from
 * RuntimeSecurityPolicy objects.
 *
 * Two families of programs are defined here:
 *
 *   - tracepoint/syscalls/sys_enter_{execve,openat,connect}: audit-only.
 *     A tracepoint's return value cannot influence the syscall outcome, so
 *     these can only observe and journal — used when this node's active LSM
 *     chain does not include "bpf" (this dev machine's WSL2 kernel today;
 *     see EXPERIMENTS_LOG.md Phase 0). The Go loader attaches these, and
 *     only these, in that case.
 *
 *   - lsm/{bprm_check_security,file_open,socket_connect}: enforce-capable.
 *     Returning a negative value actually denies the operation. The Go
 *     loader attaches these instead, once Phase 9's AKS pre-flight confirms
 *     "bpf" is in /sys/kernel/security/lsm on the real node.
 *
 *   - lsm/bpf: the "BPF-lock" defense-in-depth hook (Phase 4 requirement).
 *     Once the agent's own authorized programs are loaded, the Go loader
 *     flips bpf_lock_engaged to 1; from that point this hook denies further
 *     bpf(2) program-load syscalls on the node, closing the TOCTOU window on
 *     the agent itself. Configurable/disablable from userspace (the loader
 *     simply never sets the flag if BPFLockSpec.Enabled is false).
 */
#include "headers/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

/* Linux's internal __FMODE_EXEC bit is carried in struct file::f_flags for
 * files opened by do_open_execat(). It is not a userspace-visible O_* flag
 * and is not exported through BTF, so keep the kernel value local and give
 * it a project-specific name. The target 6.8 kernel defines it as 0x20;
 * this value has been stable across the kernels supported by this prototype.
 */
#define RUNTIME_GUARD_EXEC_OPEN_FLAG 0x20U

/* struct event is only ever referenced as a local pointer cast from
 * bpf_ringbuf_reserve() — unlike the *_rules/cgroup_configs map value types,
 * it is never a map's declared __type(value, ...), so nothing forces it into
 * this object's BTF. This unused variable is the standard bpf2go/libbpf
 * idiom to export a plain (non-map) type for Go binding generation. */
struct event *unused_event __attribute__((unused));

/* ---- Maps ---------------------------------------------------------- */

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64); /* cgroup_id */
	__type(value, struct cgroup_config);
} cgroup_configs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct path_rule_key);
	__type(value, struct rule_action);
} exec_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct path_rule_key);
	__type(value, struct rule_action);
} file_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct net_rule_key);
	__type(value, struct rule_action);
} net_rules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} bpf_lock_engaged SEC(".maps");

/* Task 05 (Experiment B1): per-CPU so increments never contend/lose a race;
 * userspace sums all CPUs' slots to get the node-wide total. See
 * common.h's COUNTER_* doc comment for exactly what each slot means. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, NUM_EVENT_COUNTERS);
	__type(key, __u32);
	__type(value, __u64);
} event_counters SEC(".maps");

/* ---- Helpers --------------------------------------------------------- */

/* Converts a signed byte count from bpf_probe_read_*_str() (which returns
 * the string length including the NUL terminator on success, or a negative
 * errno on failure) into a length clamped to [0, MAX_PATH_LEN-1], using an
 * explicit branch rather than a ternary+bitmask.
 *
 * This distinction matters and was not obvious in advance: a ternary
 * (`n > 0 ? (__u32)n - 1 : 0`) followed by a bitwise AND still left the
 * verifier unable to prove bpf_probe_read_kernel()'s size argument was
 * non-negative in emit_event() ("R2 min value is negative"), even though the
 * *unsigned* upper bound was already tight (umax=255) — the verifier tracks
 * signed and unsigned bounds separately, and arithmetic/ternary chains can
 * leave a stale negative smin (inherited from the original signed `n`, which
 * can be as low as roughly -4095 on a kernel errno) even after later
 * operations tighten the unsigned range. An explicit `if (n > limit) n =
 * limit;` branch is the idiom that reliably lets the verifier narrow *both*
 * bounds on each side of the branch — confirmed empirically against a real
 * kernel verifier run in kind (see EXPERIMENTS_LOG.md Phase 4), not merely
 * reasoned about, since prior attempts that looked correct still failed.
 */
static __always_inline __u32 clamp_len(long n)
{
	if (n <= 0)
		return 0;
	__u32 len = (__u32)n - 1;
	if (len > MAX_PATH_LEN - 1)
		len = MAX_PATH_LEN - 1;
	return len;
}

/* bpf_d_path() also returns the string length INCLUDING its trailing NUL.
 * The helper obtains that value as (end_of_buffer - returned_d_path_ptr),
 * and d_path() places the terminator in the buffer before returning the
 * pointer. Exclude it here so the BPF-side FNV-1a input exactly matches the
 * plain path string hashed by the Go loader. */
static __always_inline __u32 clamp_len_raw(long n)
{
	if (n <= 0)
		return 0;
	__u32 len = (__u32)n - 1;
	if (len > MAX_PATH_LEN - 1)
		len = MAX_PATH_LEN - 1;
	return len;
}

/* FNV-1a over a bounded, already-read local buffer. Hashing a fixed-size
 * local array (rather than following a pointer) keeps this trivially
 * verifier-safe: no unbounded loop, no pointer arithmetic past a known size.
 */
static __always_inline __u64 hash_path(const char *buf, __u32 len)
{
	__u64 hash = 0xcbf29ce484222325ULL; /* FNV offset basis */

#pragma unroll
	for (__u32 i = 0; i < MAX_PATH_LEN; i++) {
		if (i >= len)
			break;
		hash ^= (unsigned char)buf[i];
		hash *= 0x100000001b3ULL; /* FNV prime */
	}
	return hash;
}

/* IMPORTANT for the Go loader's revocation path: every call site below does
 * "if (!cfg) return 0" when no entry exists for this cgroup. In the LSM
 * programs, returning 0 means ALLOW. That is the correct behavior for a
 * cgroup that simply has no RuntimeSecurityPolicy at all (host processes,
 * unrelated system pods — "not our concern"). It is the WRONG behavior for
 * revocation: deleting a cgroup's entry to "revoke" its access would make
 * every subsequent exec/open/connect fail open (allowed), the opposite of
 * revocation. The loader must therefore revoke by UPDATING the entry to a
 * deny-by-default cgroup_config (and clearing any stale per-path/per-net
 * allow rules for that cgroup_id from exec_rules/file_rules/net_rules — an
 * old ALLOW rule would otherwise still win over the new deny-by-default),
 * never by deleting it outright.
 */
static __always_inline struct cgroup_config *get_cgroup_config(__u64 cgroup_id)
{
	return bpf_map_lookup_elem(&cgroup_configs, &cgroup_id);
}

/* Resolves the allow/deny decision for a path-based hook (exec or
 * file/device open) against the per-cgroup rule map, falling back to the
 * cgroup's configured default-allow flag when no exact-match rule exists. */
static __always_inline __u8 resolve_path_decision(void *rules_map, __u64 cgroup_id,
						   const char *path, __u32 path_len,
						   __u8 default_allow)
{
	struct path_rule_key key = {
		.cgroup_id = cgroup_id,
		.path_hash = hash_path(path, path_len),
	};
	struct rule_action *action = bpf_map_lookup_elem(rules_map, &key);
	if (action)
		return action->allow;
	return default_allow;
}

/* Resolves the allow/deny decision for connect(), checking an exact
 * (cgroup_id, dest_addr, dest_port) rule first, then falling back to a
 * (cgroup_id, dest_addr, 0) "any port" wildcard rule — port 0 is never a
 * valid connect() destination port, so it is safe to reuse as the wildcard
 * sentinel. This mirrors the RuntimeSecurityPolicy CRD's
 * "AllowedPorts: [] means any port" semantics (see
 * NetworkEgressPolicy.AllowedPorts doc comment in the Operator's API types):
 * the Go loader emits a single port=0 rule for a CIDR/IP entry that has no
 * port restriction, instead of one rule per possible port. */
static __always_inline __u8 resolve_net_decision(__u64 cgroup_id, __u32 dest_addr_v4,
						  __u16 dest_port, __u8 default_allow)
{
	struct net_rule_key key = { .cgroup_id = cgroup_id, .dest_addr_v4 = dest_addr_v4, .dest_port = dest_port };
	struct rule_action *action = bpf_map_lookup_elem(&net_rules, &key);
	if (action)
		return action->allow;

	key.dest_port = 0;
	action = bpf_map_lookup_elem(&net_rules, &key);
	if (action)
		return action->allow;

	return default_allow;
}

static __always_inline void bump_event_counter(__u32 idx)
{
	__u64 *val = bpf_map_lookup_elem(&event_counters, &idx);
	if (val)
		(*val)++;
}

static __always_inline void emit_event(__u64 cgroup_id, __u8 type, __u8 decision,
					__u8 hook_mode, const char *path, __u32 path_len,
					__u32 dest_addr_v4, __u16 dest_port)
{
	__u32 generated_idx = COUNTER_GENERATED;
	bump_event_counter(generated_idx);

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 dropped_idx = COUNTER_DROPPED;
		bump_event_counter(dropped_idx);
		return;
	}

	__builtin_memset(e, 0, sizeof(*e));
	e->cgroup_id = cgroup_id;
	e->timestamp_ns = bpf_ktime_get_ns();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->tgid = pid_tgid >> 32;
	e->pid = (__u32)pid_tgid;
	e->type = type;
	e->decision = decision;
	e->hook_mode = hook_mode;
	e->dest_addr_v4 = dest_addr_v4;
	e->dest_port = dest_port;
	if (path && path_len > 0) {
		/* Callers already clamp path_len via clamp_len/clamp_len_raw,
		 * but the verifier analyzes this always_inline body fresh at
		 * every call site, so it must be re-derived here too. An
		 * explicit if-branch (n > const ? const : n) sufficed for
		 * every tracepoint call site and the lsm_exec/lsm_connect LSM
		 * call sites, but NOT for lsm_file_open's: there the verifier
		 * still rejected this bpf_probe_read_kernel with "R2
		 * unbounded memory access, use 'var &= const' or 'if (var <
		 * const)'" -- evidently is_device's array-index reads on
		 * `path` (between clamp_len_raw() and here) leave less
		 * precision on path_len's tracked bound by the time it
		 * crosses this inline-function boundary than the tracepoint/
		 * lsm_exec/lsm_connect call sites do. An unconditional AND
		 * mask (MAX_PATH_LEN is a power of 2) gives the verifier an
		 * exact bound no branch-precision loss can undermine, and
		 * works for every call site, so it replaces the branch here
		 * rather than special-casing just lsm_file_open.
		 */
		__u32 n = path_len & (MAX_PATH_LEN - 1);
		bpf_probe_read_kernel(e->path, n, path);
	}

	bpf_ringbuf_submit(e, 0);
	__u32 emitted_idx = COUNTER_EMITTED;
	bump_event_counter(emitted_idx);
}

/* ================= Audit-only path: tracepoints ===================== */

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct cgroup_config *cfg = get_cgroup_config(cgroup_id);
	if (!cfg)
		return 0; /* no policy loaded for this cgroup: not our concern (yet) */

	char path[MAX_PATH_LEN] = {};
	long n = bpf_probe_read_user_str(path, sizeof(path), (const char *)ctx->args[0]);
	__u32 len = clamp_len(n);

	__u8 allow = resolve_path_decision(&exec_rules, cgroup_id, path, len, cfg->exec_default_allow);
	__u8 decision = allow ? DECISION_ALLOWED : DECISION_AUDIT_WOULD_DENY;
	emit_event(cgroup_id, EVENT_TYPE_EXEC, decision, HOOK_MODE_AUDIT, path, len, 0, 0);
	return 0;
}

/* Shared by trace_open and trace_openat: the two syscalls differ only in
 * which argument carries the filename pointer (open()'s is args[0],
 * openat()'s is args[1] since args[0] is the directory fd). Both must be
 * hooked: on x86_64 the legacy open(2) syscall still exists alongside
 * openat(2), and different libc/applet implementations pick one or the
 * other for the same logical "open a file" operation — busybox's `cat` was
 * empirically observed on this project's kind nodes to use plain open(),
 * which sys_enter_openat alone never sees at all (not even as a denial —
 * silently invisible), while other code paths (e.g. musl's resolver used by
 * wget) use openat(). Hooking only one of the two would make file-open
 * evidence silently incomplete for exactly the kind of process whose
 * accesses the "unauthorized file/model read" attack scenario is supposed
 * to catch. See EXPERIMENTS_LOG.md Phase 5. */
static __always_inline void handle_file_open(struct trace_event_raw_sys_enter *ctx, __u64 filename_arg_index)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct cgroup_config *cfg = get_cgroup_config(cgroup_id);
	if (!cfg)
		return;

	char path[MAX_PATH_LEN] = {};
	const char *filename_ptr = (const char *)(filename_arg_index == 0 ? ctx->args[0] : ctx->args[1]);
	long n = bpf_probe_read_user_str(path, sizeof(path), filename_ptr);
	__u32 len = clamp_len(n);

	__u8 is_device = (len > 5 && path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
			   path[3] == 'v' && path[4] == '/');
	__u8 default_allow = is_device ? cfg->device_default_allow : cfg->file_default_allow;
	__u8 allow = resolve_path_decision(&file_rules, cgroup_id, path, len, default_allow);
	__u8 decision = allow ? DECISION_ALLOWED : DECISION_AUDIT_WOULD_DENY;
	__u8 type = is_device ? EVENT_TYPE_DEVICE_OPEN : EVENT_TYPE_FILE_OPEN;
	emit_event(cgroup_id, type, decision, HOOK_MODE_AUDIT, path, len, 0, 0);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	/* open(const char *pathname, int flags, umode_t mode) */
	handle_file_open(ctx, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	/* openat(int dfd, const char *filename, int flags, umode_t mode) */
	handle_file_open(ctx, 1);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct cgroup_config *cfg = get_cgroup_config(cgroup_id);
	if (!cfg)
		return 0;

	/* connect(int fd, struct sockaddr *uservaddr, int addrlen) */
	struct sockaddr_in addr = {};
	if (bpf_probe_read_user(&addr, sizeof(addr), (const void *)ctx->args[1]) != 0)
		return 0;
	if (addr.sin_family != AF_INET)
		return 0; /* IPv6 out of scope for this phase — documented limitation */

	__u32 daddr = addr.sin_addr.s_addr;
	__u16 dport = bpf_ntohs(addr.sin_port);

	__u8 allow = resolve_net_decision(cgroup_id, daddr, dport, cfg->net_default_allow);
	__u8 decision = allow ? DECISION_ALLOWED : DECISION_AUDIT_WOULD_DENY;
	emit_event(cgroup_id, EVENT_TYPE_CONNECT, decision, HOOK_MODE_AUDIT, 0, 0, daddr, dport);
	return 0;
}

/* ================= Enforce-capable path: BPF-LSM ===================== */

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_exec, struct linux_binprm *bprm, int ret)
{
	bump_event_counter(COUNTER_LSM_HOOK_ENTERED);

	if (ret != 0)
		return ret; /* a prior LSM already denied; do not override */

	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct cgroup_config *cfg = get_cgroup_config(cgroup_id);
	if (!cfg)
		return 0;

	/* BENCHMARK-ONLY (see common.h's BENCH_MODE_* doc comment): production
	 * traffic always has benchmark_mode == BENCH_MODE_OFF and never reaches
	 * either branch below. C1 (BENCH_MODE_NOOP): return immediately, no
	 * path read, no rule-map lookup, no emit_event() -- isolates pure hook
	 * entry + cfg-lookup cost. C2 (BENCH_MODE_MAP_ONLY): do the real
	 * exec_rules lookup and return its decision, but skip emit_event() --
	 * isolates hook + map-lookup cost without the ring-buffer write. Two
	 * literal return sites here (not a shared variable folded into the one
	 * below), for the same clang -O2 branchless-codegen verifier reason
	 * documented on the two return sites further down this function. */
	if (cfg->benchmark_mode == BENCH_MODE_NOOP)
		return 0;
	if (cfg->benchmark_mode == BENCH_MODE_MAP_ONLY) {
		char bench_path[MAX_PATH_LEN] = {};
		const char *bench_filename = BPF_CORE_READ(bprm, filename);
		long bench_n = bpf_probe_read_kernel_str(bench_path, sizeof(bench_path), bench_filename);
		__u32 bench_len = clamp_len(bench_n);
		__u8 bench_allow = resolve_path_decision(&exec_rules, cgroup_id, bench_path, bench_len,
							  cfg->exec_default_allow);
		if (!bench_allow)
			return -1;
		return 0;
	}

	char path[MAX_PATH_LEN] = {};
	const char *filename = BPF_CORE_READ(bprm, filename);
	long n = bpf_probe_read_kernel_str(path, sizeof(path), filename);
	__u32 len = clamp_len(n);

	__u8 allow = resolve_path_decision(&exec_rules, cgroup_id, path, len, cfg->exec_default_allow);
	/* Two fully separate return sites, each a literal constant right at
	 * its own call site -- NOT a shared variable/ternary, and NOT fixed
	 * by barrier_var() on a shared variable either (tried both; see git
	 * history). At -O2 clang recognizes "compute a 0/-1 decision, maybe
	 * post-process it, then return it" as one semantic pattern and
	 * folds it into branchless bit-twiddling (AND/NEGATE on the boolean
	 * inputs) regardless of where in the function that pattern appears
	 * or whether a compiler barrier sits between the computation and the
	 * return -- the verifier then cannot prove the folded result stays
	 * in [-4095, 0], the range LSM programs must return into, and
	 * rejects the load ("R0 has unknown scalar value should have been
	 * in [-4095, 0]"). Reproduced identically across clang 14 and 19.
	 * Duplicating emit_event() across two independent branches, each
	 * ending in its own literal `return -1;`/`return 0;`, leaves no
	 * single value-computation site for that fold to target. First real
	 * BPF-LSM load on this campaign's cluster (Task 10); the
	 * tracepoint-only audit path never exercised this code, so this bug
	 * was latent and undetected until now.
	 */
	if (cfg->enforcement_mode == HOOK_MODE_ENFORCE && !allow) {
		emit_event(cgroup_id, EVENT_TYPE_EXEC, DECISION_DENIED,
			   HOOK_MODE_ENFORCE, path, len, 0, 0);
		return -1;
	}
	emit_event(cgroup_id, EVENT_TYPE_EXEC, allow ? DECISION_ALLOWED : DECISION_DENIED,
		   HOOK_MODE_ENFORCE, path, len, 0, 0);
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file, int ret)
{
	bump_event_counter(COUNTER_LSM_HOOK_ENTERED);

	if (ret != 0)
		return ret;

	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct cgroup_config *cfg = get_cgroup_config(cgroup_id);
	if (!cfg)
		return 0;

	/* BENCHMARK-ONLY, see lsm_exec's identical comment above. */
	if (cfg->benchmark_mode == BENCH_MODE_NOOP)
		return 0;
	if (cfg->benchmark_mode == BENCH_MODE_MAP_ONLY) {
		char bench_path[MAX_PATH_LEN] = {};
		long bench_n = bpf_d_path(&file->f_path, bench_path, sizeof(bench_path));
		__u32 bench_len = clamp_len_raw(bench_n);
		__u8 bench_is_device = (bench_len > 5 && bench_path[0] == '/' && bench_path[1] == 'd' &&
					 bench_path[2] == 'e' && bench_path[3] == 'v' && bench_path[4] == '/');
		__u8 bench_default_allow = bench_is_device ? cfg->device_default_allow : cfg->file_default_allow;
		__u8 bench_allow = resolve_path_decision(&file_rules, cgroup_id, bench_path, bench_len,
							  bench_default_allow);
		if (!bench_allow)
			return -1;
		return 0;
	}

	/* execve uses kernel-internal exec-intent opens before its bprm policy
	 * path can run. Applying the ordinary file policy to those opens would
	 * let an empty/default-deny file policy reject the executable before
	 * exec_rules can be consulted. Defer exec-intent opens to the bprm/exec
	 * policy path as applicable; ordinary userspace opens do not carry this
	 * internal flag and remain governed by file_rules. A prior LSM denial was
	 * already preserved by the ret check above. */
	unsigned int f_flags = BPF_CORE_READ(file, f_flags);
	if (f_flags & RUNTIME_GUARD_EXEC_OPEN_FLAG)
		return 0;

	char path[MAX_PATH_LEN] = {};
	long n = bpf_d_path(&file->f_path, path, sizeof(path));
	__u32 len = clamp_len_raw(n);

	__u8 is_device = (len > 5 && path[0] == '/' && path[1] == 'd' && path[2] == 'e' &&
			   path[3] == 'v' && path[4] == '/');
	__u8 default_allow = is_device ? cfg->device_default_allow : cfg->file_default_allow;
	__u8 allow = resolve_path_decision(&file_rules, cgroup_id, path, len, default_allow);
	__u8 type = is_device ? EVENT_TYPE_DEVICE_OPEN : EVENT_TYPE_FILE_OPEN;
	/* See lsm_exec's comment: two separate return sites, not a shared
	 * variable, to avoid the branchless-codegen verifier rejection. */
	if (cfg->enforcement_mode == HOOK_MODE_ENFORCE && !allow) {
		emit_event(cgroup_id, type, DECISION_DENIED,
			   HOOK_MODE_ENFORCE, path, len, 0, 0);
		return -1;
	}
	emit_event(cgroup_id, type, allow ? DECISION_ALLOWED : DECISION_DENIED,
		   HOOK_MODE_ENFORCE, path, len, 0, 0);
	return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect, struct socket *sock, struct sockaddr *address, int addrlen, int ret)
{
	bump_event_counter(COUNTER_LSM_HOOK_ENTERED);

	if (ret != 0)
		return ret;

	__u64 cgroup_id = bpf_get_current_cgroup_id();
	struct cgroup_config *cfg = get_cgroup_config(cgroup_id);
	if (!cfg)
		return 0;

	if (address->sa_family != AF_INET)
		return 0; /* IPv6 out of scope for this phase — documented limitation */

	struct sockaddr_in addr = {};
	if (bpf_core_read(&addr, sizeof(addr), address) != 0)
		return 0;

	__u32 daddr = addr.sin_addr.s_addr;
	__u16 dport = bpf_ntohs(addr.sin_port);

	/* BENCHMARK-ONLY, see lsm_exec's identical comment above. */
	if (cfg->benchmark_mode == BENCH_MODE_NOOP)
		return 0;
	if (cfg->benchmark_mode == BENCH_MODE_MAP_ONLY) {
		__u8 bench_allow = resolve_net_decision(cgroup_id, daddr, dport, cfg->net_default_allow);
		if (!bench_allow)
			return -1;
		return 0;
	}

	__u8 allow = resolve_net_decision(cgroup_id, daddr, dport, cfg->net_default_allow);
	/* See lsm_exec's comment: two separate return sites, not a shared
	 * variable, to avoid the branchless-codegen verifier rejection. */
	if (cfg->enforcement_mode == HOOK_MODE_ENFORCE && !allow) {
		emit_event(cgroup_id, EVENT_TYPE_CONNECT, DECISION_DENIED,
			   HOOK_MODE_ENFORCE, 0, 0, daddr, dport);
		return -1;
	}
	emit_event(cgroup_id, EVENT_TYPE_CONNECT, allow ? DECISION_ALLOWED : DECISION_DENIED,
		   HOOK_MODE_ENFORCE, 0, 0, daddr, dport);
	return 0;
}

/* ================= BPF-lock (defense in depth) ======================= */

SEC("lsm/bpf")
int BPF_PROG(lsm_bpf_lock, int cmd, union bpf_attr *attr, unsigned int size, int ret)
{
	if (ret != 0)
		return ret;

	__u32 zero = 0;
	__u32 *engaged = bpf_map_lookup_elem(&bpf_lock_engaged, &zero);
	if (!engaged || *engaged == 0)
		return 0; /* lock not engaged yet, or disabled by configuration */

	if (cmd == BPF_PROG_LOAD) {
		emit_event(0, EVENT_TYPE_BPF_LOAD_BLOCKED, DECISION_DENIED, HOOK_MODE_ENFORCE, 0, 0, 0, 0);
		return -1; /* -EPERM: deny further BPF program loads on this node */
	}
	return 0;
}
