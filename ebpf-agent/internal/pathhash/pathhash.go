// Package pathhash computes the exact same path hash the eBPF program
// (bpf/agent.bpf.c, hash_path()) computes in-kernel, so the userspace loader
// can populate exec_rules/file_rules with keys that will actually match at
// runtime. A mismatch here would silently break every policy — allowlisted
// paths would simply never match, and there would be no error, only a
// runtime behavior that looks like "everything is denied" or "the policy is
// ignored". This is exactly the kind of cross-language contract that needs a
// test pinning it down, not just code that looks plausible.
//
// The kernel side is a hand-rolled FNV-1a loop (offset basis
// 0xcbf29ce484222325, prime 0x100000001b3) because eBPF C cannot use a
// library. Go's standard library hash/fnv implements the identical,
// standard FNV-1a-64 algorithm with the same constants, so this package is a
// thin wrapper rather than a second hand-rolled implementation that could
// drift from the C one.
package pathhash

import "hash/fnv"

// MaxPathLen matches MAX_PATH_LEN in bpf/common.h. bpf_probe_read_*_str /
// bpf_d_path truncate to this many bytes (including, then excluding, the
// trailing NUL) before hashing, so this package must truncate identically or
// a long path would hash differently in-kernel than here.
const MaxPathLen = 256

// Hash returns the FNV-1a hash of path, truncated to MaxPathLen-1 bytes —
// bit-for-bit what the eBPF program computes for the same path at runtime.
func Hash(path string) uint64 {
	b := []byte(path)
	if len(b) > MaxPathLen-1 {
		b = b[:MaxPathLen-1]
	}
	h := fnv.New64a()
	_, _ = h.Write(b) // hash.Hash64's Write never returns an error
	return h.Sum64()
}
