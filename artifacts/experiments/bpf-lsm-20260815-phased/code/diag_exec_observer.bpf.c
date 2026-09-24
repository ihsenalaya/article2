/* SPDX-License-Identifier: GPL-2.0
 *
 * Temporary, non-enforcing diagnostic observer for the RuntimeGuard phase-4
 * investigation. It records the exact linux_binprm filename seen by
 * bprm_check_security and the resolved path/f_mode seen by file_open.
 * Returning the incoming value unchanged makes both observers policy-neutral.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define PATH_BUF_LEN 256

struct exec_observation {
	__u64 cgroup_id;
	__u64 path_hash;
	__s32 incoming_ret;
	__u32 path_len;
	char path[PATH_BUF_LEN];
};

struct file_observation {
	__u64 cgroup_id;
	__u64 f_mode;
	__u64 f_flags;
	__s32 incoming_ret;
	__u32 path_len;
	char path[PATH_BUF_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct exec_observation);
} exec_observations SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, struct file_observation);
} file_observations SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(observe_exec, struct linux_binprm *bprm, int ret)
{
	struct exec_observation observation = {};
	observation.cgroup_id = bpf_get_current_cgroup_id();
	observation.incoming_ret = ret;

	const char *filename = BPF_CORE_READ(bprm, filename);
	long n = bpf_probe_read_kernel_str(observation.path,
					   sizeof(observation.path), filename);
	if (n > 0) {
		__u32 len = (__u32)n - 1;
		if (len > PATH_BUF_LEN - 1)
			len = PATH_BUF_LEN - 1;
		observation.path_len = len;
	}

	bpf_map_update_elem(&exec_observations, &observation.cgroup_id,
			    &observation, BPF_ANY);
	return ret;
}

SEC("lsm/file_open")
int BPF_PROG(observe_file_open, struct file *file, int ret)
{
	struct file_observation observation = {};
	observation.cgroup_id = bpf_get_current_cgroup_id();
	observation.f_mode = BPF_CORE_READ(file, f_mode);
	observation.f_flags = BPF_CORE_READ(file, f_flags);
	observation.incoming_ret = ret;

	long n = bpf_d_path(&file->f_path, observation.path,
			    sizeof(observation.path));
	if (n > 0) {
		__u32 len = (__u32)n;
		if (len > PATH_BUF_LEN - 1)
			len = PATH_BUF_LEN - 1;
		observation.path_len = len;
	}

	bpf_map_update_elem(&file_observations, &observation.cgroup_id,
			    &observation, BPF_ANY);
	return ret;
}
