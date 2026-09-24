package controller

import (
	"reflect"
	"testing"

	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

func TestApplyPolicyRequestsKeepExecAndFileIndependent(t *testing.T) {
	material := policyHashMaterial{}
	material.EnforcementMode = "audit"
	material.Exec.DefaultAction = "deny"
	material.FileAccess.DefaultAction = "deny"

	applyExecPolicyRequest(&material, &placementtoken.ExecPolicyRequest{
		EnforcementMode: "enforce",
		DefaultAction:   "deny",
		AllowedPaths:    []string{"/bin/true"},
	})

	if material.EnforcementMode != "enforce" {
		t.Fatalf("EnforcementMode = %q, want enforce", material.EnforcementMode)
	}
	if !reflect.DeepEqual(material.Exec.AllowedPaths, []string{"/bin/true"}) {
		t.Fatalf("Exec.AllowedPaths = %v, want [/bin/true]", material.Exec.AllowedPaths)
	}
	if material.FileAccess.DefaultAction != "deny" || len(material.FileAccess.AllowedPathPrefixes) != 0 {
		t.Fatalf("exec request unexpectedly broadened file policy: %+v", material.FileAccess)
	}

	applyFilePolicyRequest(&material, &placementtoken.FilePolicyRequest{
		DefaultAction: "deny",
		AllowedPaths:  []string{"/lib/libm.so.6", "/lib/libc.so.6"},
	})

	if !reflect.DeepEqual(material.FileAccess.AllowedPathPrefixes, []string{"/lib/libm.so.6", "/lib/libc.so.6"}) {
		t.Fatalf("FileAccess.AllowedPathPrefixes = %v", material.FileAccess.AllowedPathPrefixes)
	}
	if !reflect.DeepEqual(material.Exec.AllowedPaths, []string{"/bin/true"}) {
		t.Fatalf("file request unexpectedly changed exec policy: %+v", material.Exec)
	}
}

func TestApplyFilePolicyRequestInvalidDefaultFailsSafe(t *testing.T) {
	material := policyHashMaterial{}
	material.FileAccess.DefaultAction = "deny"

	applyFilePolicyRequest(&material, &placementtoken.FilePolicyRequest{
		DefaultAction: "invalid",
		AllowedPaths:  []string{"/lib/libc.so.6"},
	})

	if material.FileAccess.DefaultAction != "deny" {
		t.Fatalf("invalid default changed fail-safe action to %q", material.FileAccess.DefaultAction)
	}
	if !reflect.DeepEqual(material.FileAccess.AllowedPathPrefixes, []string{"/lib/libc.so.6"}) {
		t.Fatalf("valid allow entries were not copied: %v", material.FileAccess.AllowedPathPrefixes)
	}
}
