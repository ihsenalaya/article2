/* SPDX-License-Identifier: GPL-2.0
 *
 * Phase 3 minimal BPF-LSM test — same independence guarantee as Phase 2
 * (minimal.bpf.c), but the hardcoded string compare is replaced by a real
 * BPF_MAP_TYPE_HASH lookup populated from userspace: exactly the mechanism
 * (LSM hook + map lookup + decision) Phase 3 exists to demonstrate
 * separately from Phase 2's hardcoded version and from RuntimeGuard itself.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define KEY_LEN 32

struct path_key {
	char path[KEY_LEN];
};

/* value: 1 = ALLOW, 0 = DENY. Absence of a key = default allow (mirrors
 * RuntimeGuard's own "no policy for this identity = not our concern" default,
 * see agent.bpf.c's get_cgroup_config doc comment) -- this hook is
 * system-wide (no cgroup scoping here, unlike RuntimeGuard), so every other
 * process's exec on this VM (sshd, cron, bash, ...) must default-allow or
 * the box becomes unusable. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8);
	__type(key, struct path_key);
	__type(value, __u8);
} decisions SEC(".maps");

/* counters[0]=hook_entered [1]=deny_decisions [2]=allow_decisions(mapped)
 * [3]=allow_decisions(no_map_entry, default) */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 4);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &idx);
	if (v)
		__sync_fetch_and_add(v, 1);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(map_lsm_exec, struct linux_binprm *bprm, int ret)
{
	bump(0);

	if (ret != 0)
		return ret;

	struct path_key key = {};
	const char *filename = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(key.path, sizeof(key.path), filename);

	__u8 *decision = bpf_map_lookup_elem(&decisions, &key);
	if (!decision) {
		bump(3);
		return 0;
	}

	/* Two separate return sites -- see minimal.bpf.c's comment on the
	 * clang -O2 branchless-fold verifier rejection this avoids. */
	if (*decision == 0) {
		bump(1);
		return -1; /* -EPERM */
	}
	bump(2);
	return 0;
}
