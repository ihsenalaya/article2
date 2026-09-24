package pathhash

import (
	"strings"
	"testing"
)

// Reference values below were produced by compiling and running a standalone
// host binary of the *exact* hash_path() loop from bpf/agent.bpf.c (not the
// BPF-target build, a plain -o hash_ref host binary; see
// EXPERIMENTS_LOG.md Phase 4 for the exact commands). This is a real
// cross-language check, not an assumption that "FNV-1a should match" — Go's
// hash/fnv is used here as an implementation detail, but what's actually
// under test is that this package's truncation/byte-feeding behavior
// produces bit-identical output to the C program the kernel will run.
func TestHash_MatchesCReferenceImplementation(t *testing.T) {
	cases := []struct {
		path string
		want uint64
	}{
		{"", 14695981039346656037},
		{"/bin/bash", 16212956474401450090},
		{"/usr/bin/curl", 2042273892392317701},
		{"/models/weights.bin", 5656580627118625273},
	}
	for _, c := range cases {
		got := Hash(c.path)
		if got != c.want {
			t.Errorf("Hash(%q) = %d, want %d (C reference)", c.path, got, c.want)
		}
	}
}

func TestHash_Deterministic(t *testing.T) {
	a := Hash("/usr/bin/curl")
	b := Hash("/usr/bin/curl")
	if a != b {
		t.Fatalf("expected deterministic hash, got %d vs %d", a, b)
	}
}

func TestHash_DifferentPathsDifferentHashes(t *testing.T) {
	a := Hash("/bin/bash")
	b := Hash("/bin/sh")
	if a == b {
		t.Fatal("expected distinct hashes for distinct paths (collision, or bug)")
	}
}

func TestHash_TruncatesLikeKernelSide(t *testing.T) {
	// A path longer than MaxPathLen-1 must hash identically to its
	// MaxPathLen-1-byte truncation, because that's exactly what
	// bpf_probe_read_user_str()/bpf_d_path() truncate to in-kernel before
	// hash_path() ever sees the bytes. If this package hashed the full
	// (untruncated) string instead, long paths would never match their
	// in-kernel counterpart.
	longPath := "/" + strings.Repeat("a", 500)
	truncated := longPath[:MaxPathLen-1]

	if Hash(longPath) != Hash(truncated) {
		t.Fatal("expected Hash to truncate to MaxPathLen-1 bytes before hashing, matching the kernel side")
	}
}
