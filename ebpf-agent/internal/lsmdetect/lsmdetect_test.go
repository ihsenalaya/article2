package lsmdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func writeLSMFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "lsm")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write lsm file: %v", err)
	}
	return path
}

func TestBPFLSMActive_Present(t *testing.T) {
	path := writeLSMFile(t, "lockdown,yama,bpf,apparmor\n")
	if !BPFLSMActive(path) {
		t.Fatal("expected bpf to be detected as active")
	}
}

func TestBPFLSMActive_Absent(t *testing.T) {
	// This is the real value found on this project's dev kernel in Phase 0.
	path := writeLSMFile(t, "landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo\n")
	if BPFLSMActive(path) {
		t.Fatal("expected bpf to be detected as inactive")
	}
}

func TestBPFLSMActive_FileMissing(t *testing.T) {
	if BPFLSMActive("/nonexistent/path/for/testing/lsm") {
		t.Fatal("expected missing file to be treated as bpf inactive, not an error")
	}
}

func TestBPFLSMActive_DoesNotSubstringMatch(t *testing.T) {
	// A guard against a naive strings.Contains implementation: "bpfilter" or
	// "ebpf-something" must not be confused with the literal LSM name "bpf".
	path := writeLSMFile(t, "landlock,bpfilter,apparmor\n")
	if BPFLSMActive(path) {
		t.Fatal("expected 'bpfilter' entry to not be confused with 'bpf'")
	}
}

func TestDetermineMode_EnforceWhenActive(t *testing.T) {
	path := writeLSMFile(t, "bpf\n")
	if got := DetermineMode(path); got != ModeEnforce {
		t.Fatalf("expected ModeEnforce, got %s", got)
	}
}

func TestDetermineMode_AuditWhenInactive(t *testing.T) {
	path := writeLSMFile(t, "apparmor\n")
	if got := DetermineMode(path); got != ModeAudit {
		t.Fatalf("expected ModeAudit, got %s", got)
	}
}

func TestDetermineMode_AuditWhenFileMissing(t *testing.T) {
	if got := DetermineMode("/nonexistent/path"); got != ModeAudit {
		t.Fatalf("expected ModeAudit when lsm file is missing, got %s", got)
	}
}
