/* SPDX-License-Identifier: GPL-2.0
 *
 * Phase 2 minimal BPF-LSM test — completely independent of RuntimeGuard
 * (no shared code, no shared maps, no shared program). Single hardcoded
 * decision: exec of exactly "/tmp/runtimeguard-deny-target" -> -EPERM,
 * everything else -> allow (return 0).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_BUF_LEN 128
#define DENY_PATH "/tmp/runtimeguard-deny-target"
#define DENY_PATH_LEN 29 /* strlen(DENY_PATH), excluding NUL */

/* counters[0] = hook entered, counters[1] = deny decisions, counters[2] = allow decisions */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

/* Fixed-length, constant-index comparison only (every index into path/want is
 * a compile-time constant from #pragma unroll) -- the same verifier-safe
 * pattern RuntimeGuard's own hash_path() in ebpf-agent/bpf/agent.bpf.c uses,
 * deliberately avoided any variable-offset indexing (e.g. a suffix match)
 * which would require the verifier to bound a runtime-computed start offset.
 */
static __always_inline int path_is_deny_target(const char *path, __u32 len)
{
	if (len != DENY_PATH_LEN)
		return 0;

	const char want[] = DENY_PATH;
#pragma unroll
	for (__u32 i = 0; i < DENY_PATH_LEN; i++) {
		if (path[i] != want[i])
			return 0;
	}
	return 1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(minimal_lsm_exec, struct linux_binprm *bprm, int ret)
{
	bump(0); /* hook entered -- unconditional, before any decision logic */

	if (ret != 0)
		return ret; /* an earlier LSM already denied; do not override */

	char path[PATH_BUF_LEN] = {};
	const char *filename = BPF_CORE_READ(bprm, filename);
	long n = bpf_probe_read_kernel_str(path, sizeof(path), filename);
	if (n <= 0)
		return 0;
	__u32 len = (__u32)n - 1; /* bpf_probe_read_kernel_str's return includes the NUL */
	if (len > PATH_BUF_LEN - 1)
		len = PATH_BUF_LEN - 1;

	/* Two separate return sites (not a shared variable) -- RuntimeGuard's
	 * own lsm_exec hit a real clang -O2 verifier rejection folding a
	 * ternary/shared-variable decision into branchless bit-twiddling the
	 * verifier could not bound into [-4095, 0]. Avoided here from the
	 * start rather than discovered the hard way again. */
	if (path_is_deny_target(path, len)) {
		bump(1);
		return -1; /* -EPERM */
	}
	bump(2);
	return 0;
}
