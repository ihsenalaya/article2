package cgroupmap

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const (
	guaranteedUID = "550e8400-e29b-41d4-a716-446655440000"
	burstableUID  = "a1b2c3d4-1111-2222-3333-444455556666"
)

// buildFakeCgroupTree creates a temp directory simulating a real cgroup v2
// layout under both kubelet cgroup drivers, including the nested
// per-container leaf cgroup ("cri-containerd-*.scope") empirically observed
// on this project's kind nodes (see EXPERIMENTS_LOG.md Phase 5) — a pod-level
// directory with no leaf underneath it would not reflect where real
// container processes' bpf_get_current_cgroup_id() actually resolves to.
func buildFakeCgroupTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// systemd driver, Guaranteed QoS (no intermediate QoS slice), single
	// container leaf cgroup nested underneath:
	// kubepods.slice/kubepods-pod<uid_with_underscores>.slice/cri-containerd-aaaa.scope/
	systemdGuaranteed := filepath.Join(root,
		"kubepods.slice",
		"kubepods-pod"+dashedToUnderscored(guaranteedUID)+".slice",
		"cri-containerd-aaaa1111.scope",
	)
	if err := os.MkdirAll(systemdGuaranteed, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// systemd driver, Burstable QoS, two container leaf cgroups (multi-container pod):
	// kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-{a,b}.scope/
	burstableBase := filepath.Join(root,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+dashedToUnderscored(burstableUID)+".slice",
	)
	if err := os.MkdirAll(filepath.Join(burstableBase, "cri-containerd-bbbb1111.scope"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(burstableBase, "cri-containerd-bbbb2222.scope"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	return root
}

func TestFindPodCgroupPath_SystemdDriverGuaranteedQoS(t *testing.T) {
	root := buildFakeCgroupTree(t)

	path, err := FindPodCgroupPath(root, guaranteedUID)
	if err != nil {
		t.Fatalf("FindPodCgroupPath: %v", err)
	}
	want := filepath.Join(root, "kubepods.slice", "kubepods-pod"+dashedToUnderscored(guaranteedUID)+".slice")
	if path != want {
		t.Fatalf("got path %q, want %q", path, want)
	}
}

func TestFindPodCgroupPath_SystemdDriverBurstableQoS(t *testing.T) {
	root := buildFakeCgroupTree(t)

	path, err := FindPodCgroupPath(root, burstableUID)
	if err != nil {
		t.Fatalf("FindPodCgroupPath: %v", err)
	}
	want := filepath.Join(root, "kubepods.slice", "kubepods-burstable.slice",
		"kubepods-burstable-pod"+dashedToUnderscored(burstableUID)+".slice")
	if path != want {
		t.Fatalf("got path %q, want %q", path, want)
	}
}

func TestFindPodCgroupPath_CgroupfsDriver(t *testing.T) {
	root := t.TempDir()
	uid := "11112222-3333-4444-5555-666677778888"
	dir := filepath.Join(root, "kubepods", "besteffort", "pod"+uid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	path, err := FindPodCgroupPath(root, uid)
	if err != nil {
		t.Fatalf("FindPodCgroupPath: %v", err)
	}
	if path != dir {
		t.Fatalf("got path %q, want %q", path, dir)
	}
}

func TestFindPodCgroupPath_NotFound(t *testing.T) {
	root := buildFakeCgroupTree(t)

	_, err := FindPodCgroupPath(root, "00000000-0000-0000-0000-000000000000")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFindPodCgroupPath_EmptyUID(t *testing.T) {
	root := buildFakeCgroupTree(t)
	if _, err := FindPodCgroupPath(root, ""); err == nil {
		t.Fatal("expected error for empty pod UID")
	}
}

func TestFindPodCgroupPath_DoesNotConfuseSubstringUIDs(t *testing.T) {
	// A pod UID that is a strict substring of another pod's UID directory
	// name must not match the wrong pod — this guards against a naive
	// strings.Contains false positive between two real pods on the node.
	root := t.TempDir()
	longUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	shortUID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeee" // one character shorter, a prefix of longUID

	longDir := filepath.Join(root, "kubepods", "pod"+longUID)
	if err := os.MkdirAll(longDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// shortUID has no real cgroup directory in this test tree — it must be
	// reported as not found, not accidentally matched against longDir.
	_, err := FindPodCgroupPath(root, shortUID)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for a pod UID with no real cgroup, got %v", err)
	}
}

func TestFindLeafCgroupPaths_SingleContainer(t *testing.T) {
	root := buildFakeCgroupTree(t)

	leaves, err := FindLeafCgroupPaths(root, guaranteedUID)
	if err != nil {
		t.Fatalf("FindLeafCgroupPaths: %v", err)
	}
	if len(leaves) != 1 {
		t.Fatalf("expected 1 leaf cgroup, got %d: %v", len(leaves), leaves)
	}
	want := filepath.Join(root, "kubepods.slice", "kubepods-pod"+dashedToUnderscored(guaranteedUID)+".slice", "cri-containerd-aaaa1111.scope")
	if leaves[0] != want {
		t.Fatalf("got leaf %q, want %q", leaves[0], want)
	}
}

func TestFindLeafCgroupPaths_MultiContainer(t *testing.T) {
	root := buildFakeCgroupTree(t)

	leaves, err := FindLeafCgroupPaths(root, burstableUID)
	if err != nil {
		t.Fatalf("FindLeafCgroupPaths: %v", err)
	}
	if len(leaves) != 2 {
		t.Fatalf("expected 2 leaf cgroups (multi-container pod), got %d: %v", len(leaves), leaves)
	}
}

func TestFindLeafCgroupPaths_FallsBackToPodDirWhenNoNesting(t *testing.T) {
	// A cgroup driver/runtime combination with no further per-container
	// nesting must still resolve to *something* (the pod dir itself), not
	// silently return zero leaves.
	root := t.TempDir()
	uid := "22223333-4444-5555-6666-777788889999"
	dir := filepath.Join(root, "kubepods", "pod"+uid)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	leaves, err := FindLeafCgroupPaths(root, uid)
	if err != nil {
		t.Fatalf("FindLeafCgroupPaths: %v", err)
	}
	if len(leaves) != 1 || leaves[0] != dir {
		t.Fatalf("expected fallback to pod dir itself, got %v", leaves)
	}
}

func TestCgroupID_ReturnsInodeNumber(t *testing.T) {
	dir := t.TempDir()
	id, err := CgroupID(dir)
	if err != nil {
		t.Fatalf("CgroupID: %v", err)
	}
	if id == 0 {
		t.Fatal("expected non-zero cgroup ID (inode number)")
	}
}

func TestCgroupID_NonExistentPath(t *testing.T) {
	if _, err := CgroupID("/nonexistent/path/for/testing"); err == nil {
		t.Fatal("expected error for non-existent path")
	}
}

func TestPodLeafCgroupIDs_EndToEnd(t *testing.T) {
	root := buildFakeCgroupTree(t)

	ids, err := PodLeafCgroupIDs(root, guaranteedUID)
	if err != nil {
		t.Fatalf("PodLeafCgroupIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] == 0 {
		t.Fatalf("expected 1 non-zero cgroup ID, got %v", ids)
	}
}

func TestResolver_TrackAndLookupBothDirections(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	ids, err := r.Track(guaranteedUID)
	if err != nil {
		t.Fatalf("Track: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected 1 cgroup ID for single-container pod, got %d", len(ids))
	}

	gotIDs, ok := r.CgroupIDsFor(guaranteedUID)
	if !ok || len(gotIDs) != 1 || gotIDs[0] != ids[0] {
		t.Fatalf("CgroupIDsFor: got (%v, %v), want (%v, true)", gotIDs, ok, ids)
	}

	gotUID, ok := r.PodUIDFor(ids[0])
	if !ok || gotUID != guaranteedUID {
		t.Fatalf("PodUIDFor: got (%q, %v), want (%q, true)", gotUID, ok, guaranteedUID)
	}

	if r.Len() != 1 {
		t.Fatalf("expected 1 tracked pod, got %d", r.Len())
	}
}

func TestResolver_TrackMultiContainerPod(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	ids, err := r.Track(burstableUID)
	if err != nil {
		t.Fatalf("Track: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 cgroup IDs for the multi-container pod, got %d", len(ids))
	}
	// Both leaf cgroup IDs must resolve back to the same pod.
	for _, id := range ids {
		uid, ok := r.PodUIDFor(id)
		if !ok || uid != burstableUID {
			t.Fatalf("PodUIDFor(%d): got (%q, %v), want (%q, true)", id, uid, ok, burstableUID)
		}
	}
}

func TestResolver_TrackRemovesReverseMappingForVanishedLeaf(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	podBase := filepath.Join(root,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+dashedToUnderscored(burstableUID)+".slice",
	)
	sandboxPath := filepath.Join(podBase, "cri-containerd-bbbb1111.scope")
	appPath := filepath.Join(podBase, "cri-containerd-bbbb2222.scope")
	sandboxID, err := CgroupID(sandboxPath)
	if err != nil {
		t.Fatalf("sandbox CgroupID: %v", err)
	}
	appID, err := CgroupID(appPath)
	if err != nil {
		t.Fatalf("app CgroupID: %v", err)
	}

	ids, err := r.Track(burstableUID)
	if err != nil {
		t.Fatalf("initial Track: %v", err)
	}
	if len(ids) != 2 {
		t.Fatalf("expected sandbox and app IDs, got %v", ids)
	}

	// Model the teardown ordering observed on containerd: the application
	// cgroup disappears first while the pause sandbox remains for one more
	// reconciliation cycle.
	if err := os.Remove(appPath); err != nil {
		t.Fatalf("remove app leaf: %v", err)
	}
	ids, err = r.Track(burstableUID)
	if err != nil {
		t.Fatalf("refresh Track: %v", err)
	}
	if len(ids) != 1 || ids[0] != sandboxID {
		t.Fatalf("expected only sandbox ID %d after app exit, got %v", sandboxID, ids)
	}
	if _, ok := r.PodUIDFor(appID); ok {
		t.Fatalf("vanished app cgroup ID %d still has a reverse mapping", appID)
	}
	if owner, ok := r.PodUIDFor(sandboxID); !ok || owner != burstableUID {
		t.Fatalf("sandbox owner: got (%q, %v), want (%q, true)", owner, ok, burstableUID)
	}
}

func TestResolver_TrackDoesNotDeleteReusedIDOwnedByAnotherPod(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	appPath := filepath.Join(root,
		"kubepods.slice",
		"kubepods-burstable.slice",
		"kubepods-burstable-pod"+dashedToUnderscored(burstableUID)+".slice",
		"cri-containerd-bbbb2222.scope",
	)
	appID, err := CgroupID(appPath)
	if err != nil {
		t.Fatalf("app CgroupID: %v", err)
	}
	if _, err := r.Track(burstableUID); err != nil {
		t.Fatalf("initial Track: %v", err)
	}

	// Simulate kernel reuse of the vanished app cgroup's numeric ID before
	// this pod refreshes its old snapshot. The replacement pod now owns the
	// reverse mapping even though burstableUID still remembers appID in its
	// prior uidToCgroups entry.
	const replacementUID = "99990000-aaaa-bbbb-cccc-ddddeeeeffff"
	r.mu.Lock()
	r.uidToCgroups[replacementUID] = []uint64{appID}
	r.cgroupToUID[appID] = replacementUID
	r.mu.Unlock()

	if err := os.Remove(appPath); err != nil {
		t.Fatalf("remove reused app leaf: %v", err)
	}
	if _, err := r.Track(burstableUID); err != nil {
		t.Fatalf("refresh original pod: %v", err)
	}
	if owner, ok := r.PodUIDFor(appID); !ok || owner != replacementUID {
		t.Fatalf("reused ID owner: got (%q, %v), want (%q, true)", owner, ok, replacementUID)
	}
}

func TestResolver_Untrack(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	ids, err := r.Track(guaranteedUID)
	if err != nil {
		t.Fatalf("Track: %v", err)
	}

	removedIDs, ok := r.Untrack(guaranteedUID)
	if !ok || len(removedIDs) != len(ids) {
		t.Fatalf("Untrack: got (%v, %v), want (%v, true)", removedIDs, ok, ids)
	}

	if _, ok := r.CgroupIDsFor(guaranteedUID); ok {
		t.Fatal("expected pod UID to be untracked")
	}
	if _, ok := r.PodUIDFor(ids[0]); ok {
		t.Fatal("expected cgroup ID to be untracked (reverse map not cleaned up)")
	}
	if r.Len() != 0 {
		t.Fatalf("expected 0 tracked pods after untrack, got %d", r.Len())
	}
}

func TestResolver_UntrackDoesNotDeleteReusedIDOwnedByAnotherPod(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	ids, err := r.Track(guaranteedUID)
	if err != nil {
		t.Fatalf("Track original pod: %v", err)
	}
	if len(ids) != 1 {
		t.Fatalf("expected one original cgroup ID, got %v", ids)
	}

	const replacementUID = "88880000-aaaa-bbbb-cccc-ddddeeeeffff"
	r.mu.Lock()
	r.uidToCgroups[replacementUID] = []uint64{ids[0]}
	r.cgroupToUID[ids[0]] = replacementUID
	r.mu.Unlock()

	if _, ok := r.Untrack(guaranteedUID); !ok {
		t.Fatal("expected original pod to be tracked")
	}
	if owner, ok := r.PodUIDFor(ids[0]); !ok || owner != replacementUID {
		t.Fatalf("reused ID owner after Untrack: got (%q, %v), want (%q, true)", owner, ok, replacementUID)
	}
}

func TestResolver_UntrackUnknownPod(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	if _, ok := r.Untrack("never-tracked-uid"); ok {
		t.Fatal("expected Untrack to report false for a pod that was never tracked")
	}
}

func TestResolver_TrackMultiplePods(t *testing.T) {
	root := buildFakeCgroupTree(t)
	r := NewResolver(root)

	if _, err := r.Track(guaranteedUID); err != nil {
		t.Fatalf("Track guaranteed: %v", err)
	}
	if _, err := r.Track(burstableUID); err != nil {
		t.Fatalf("Track burstable: %v", err)
	}
	if r.Len() != 2 {
		t.Fatalf("expected 2 tracked pods, got %d", r.Len())
	}

	gIDs, _ := r.CgroupIDsFor(guaranteedUID)
	bIDs, _ := r.CgroupIDsFor(burstableUID)
	if gIDs[0] == bIDs[0] {
		t.Fatal("expected distinct cgroup IDs for distinct pods")
	}
}
