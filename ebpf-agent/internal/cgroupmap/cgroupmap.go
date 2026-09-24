// Package cgroupmap resolves the mapping between a Kubernetes pod UID and its
// cgroup v2 ID(s) on the local node. This is the most fragile part of the
// whole system (per the experiment plan): the eBPF hooks only ever see a
// numeric cgroup ID (via bpf_get_current_cgroup_id()), never a pod UID, so
// every enforcement/evidence decision depends on this mapping being correct.
//
// The cgroup ID used by bpf_get_current_cgroup_id() is the kernfs node ID of
// the cgroup's directory under the default cgroup v2 hierarchy, which is the
// same value as that directory's inode number (stat().st_ino) — this is the
// same technique used by Cilium/Tetragon, not a project-specific assumption.
//
// Kubernetes lays out per-pod cgroups differently depending on the kubelet's
// configured cgroup driver:
//   - systemd driver:  .../kubepods.slice/kubepods-<qos>.slice/kubepods-<qos>-pod<uid_with_underscores>.slice/
//   - cgroupfs driver: .../kubepods/<qos>/pod<uid-with-dashes>/
//
// (<qos> segments are absent entirely for Guaranteed-QoS pods; the exact
// prefix chain also varies by runtime — e.g. this project's kind nodes were
// observed nesting under an additional "kubelet.slice/kubelet-kubepods.slice/"
// level. FindPodCgroupPath does not hard-code any of this, it walks and
// pattern-matches on the trailing "pod<uid>" component only.)
//
// Critically, the pod-level directory above is *not* where
// bpf_get_current_cgroup_id() resolves to for an actual container process:
// containerd/CRI create one further nested "leaf" cgroup per container
// underneath it (e.g. ".../pod<uid>.slice/cri-containerd-<id>.scope/"), and
// cgroup v2's "no internal process" constraint means only leaf cgroups ever
// actually hold PIDs. This was verified empirically on this project's kind
// nodes (see EXPERIMENTS_LOG.md Phase 5) — not assumed — and matters a great
// deal: resolving only the pod-level directory's inode, as an earlier version
// of this package did, would silently never match any real process's
// cgroup ID, meaning every policy would appear to load correctly but never
// actually apply to anything. A pod with N containers therefore has N leaf
// cgroup IDs, all of which must map to the same policy.
package cgroupmap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// ErrNotFound is returned when no cgroup directory for the given pod UID
// could be located under the configured cgroup root.
var ErrNotFound = fmt.Errorf("cgroup not found for pod UID")

// dashedToUnderscored converts a pod UID's dash form to the underscore form
// systemd unit names use (systemd escapes '-' as '_' in slice names).
func dashedToUnderscored(uid string) string {
	return strings.ReplaceAll(uid, "-", "_")
}

// candidateNameFragments returns the substrings that, if present in a cgroup
// directory's basename, identify it as belonging to podUID.
func candidateNameFragments(podUID string) []string {
	underscored := dashedToUnderscored(podUID)
	return []string{
		"pod" + podUID,      // cgroupfs driver: "pod<uid-with-dashes>"
		"pod" + underscored, // systemd driver:  "kubepods-...-pod<uid_with_underscores>.slice"
	}
}

// FindPodCgroupPath walks cgroupRoot (typically "/sys/fs/cgroup") looking for
// the pod-level cgroup v2 directory belonging to podUID. It returns the first
// matching directory's path. Note: this is *not* the leaf cgroup a container
// process actually runs in — see FindLeafCgroupPaths and the package doc.
func FindPodCgroupPath(cgroupRoot, podUID string) (string, error) {
	if podUID == "" {
		return "", fmt.Errorf("pod UID must not be empty")
	}
	fragments := candidateNameFragments(podUID)

	var found string
	err := filepath.WalkDir(cgroupRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Permission-denied or transient errors on individual cgroup
			// subdirectories (common under /sys/fs/cgroup) should not abort
			// the whole walk — skip and keep looking.
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		base := d.Name()
		for _, frag := range fragments {
			// Anchored match only: either the whole basename is exactly
			// "pod<uid>" (cgroupfs driver), or it ends in "pod<uid>.slice"
			// (systemd driver). A plain substring check would let one pod's
			// UID match another pod's cgroup whenever one UID is a string
			// prefix of the other (e.g. "...eeee" vs "...eee") — caught by
			// TestFindPodCgroupPath_DoesNotConfuseSubstringUIDs.
			if base == frag || strings.HasSuffix(base, frag+".slice") {
				found = path
				return filepath.SkipAll
			}
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("walk cgroup root %s: %w", cgroupRoot, err)
	}
	if found == "" {
		return "", fmt.Errorf("%w: %s (root %s)", ErrNotFound, podUID, cgroupRoot)
	}
	return found, nil
}

// FindLeafCgroupPaths returns every leaf cgroup directory (one per
// container) under podUID's pod-level cgroup directory. A directory is
// treated as a leaf if it contains no further subdirectories — cgroup v2's
// "no internal process" constraint means only leaf cgroups ever hold PIDs,
// so this is runtime-agnostic (works regardless of whether containerd names
// the per-container cgroup "cri-containerd-*.scope", "docker-*.scope", or
// anything else).
func FindLeafCgroupPaths(cgroupRoot, podUID string) ([]string, error) {
	podPath, err := FindPodCgroupPath(cgroupRoot, podUID)
	if err != nil {
		return nil, err
	}

	var leaves []string
	err = filepath.WalkDir(podPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		hasSubdir, err := dirHasSubdir(path)
		if err != nil {
			return nil
		}
		if !hasSubdir {
			leaves = append(leaves, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk pod cgroup %s: %w", podPath, err)
	}
	if len(leaves) == 0 {
		// The pod-level directory itself had no subdirectories at all —
		// treat it as its own leaf (e.g. a runtime/cgroup-driver
		// combination that does not nest a further nest per-container
		// cgroup). Documented fallback, not silently dropping the pod.
		leaves = append(leaves, podPath)
	}
	return leaves, nil
}

func dirHasSubdir(path string) (bool, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return false, err
	}
	for _, e := range entries {
		if e.IsDir() {
			return true, nil
		}
	}
	return false, nil
}

// CgroupID returns the cgroup v2 ID (kernfs node ID / directory inode number)
// for the cgroup directory at path. This is the same numeric value the eBPF
// program observes via bpf_get_current_cgroup_id() for processes running in
// that cgroup.
func CgroupID(path string) (uint64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat cgroup path %s: %w", path, err)
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("unsupported platform: cannot read inode number for %s", path)
	}
	return sys.Ino, nil
}

// PodCgroupID resolves podUID directly to its pod-level cgroup ID in one
// call. Deprecated for enforcement purposes in favor of PodLeafCgroupIDs —
// kept because the pod-level ID is still a valid, stable identifier for the
// pod as a whole (e.g. for logging), it is simply not what
// bpf_get_current_cgroup_id() returns for a container process.
func PodCgroupID(cgroupRoot, podUID string) (uint64, error) {
	path, err := FindPodCgroupPath(cgroupRoot, podUID)
	if err != nil {
		return 0, err
	}
	return CgroupID(path)
}

// PodLeafCgroupIDs resolves podUID to every leaf (per-container) cgroup ID —
// the IDs actual container processes report via bpf_get_current_cgroup_id().
func PodLeafCgroupIDs(cgroupRoot, podUID string) ([]uint64, error) {
	paths, err := FindLeafCgroupPaths(cgroupRoot, podUID)
	if err != nil {
		return nil, err
	}
	ids := make([]uint64, 0, len(paths))
	for _, p := range paths {
		id, err := CgroupID(p)
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// Resolver maintains a live pod UID <-> leaf cgroup ID(s) mapping for the
// node. Safe for concurrent use.
type Resolver struct {
	cgroupRoot string

	mu           sync.RWMutex
	uidToCgroups map[string][]uint64
	cgroupToUID  map[uint64]string
}

// NewResolver creates a Resolver rooted at cgroupRoot (typically "/sys/fs/cgroup").
func NewResolver(cgroupRoot string) *Resolver {
	return &Resolver{
		cgroupRoot:   cgroupRoot,
		uidToCgroups: make(map[string][]uint64),
		cgroupToUID:  make(map[uint64]string),
	}
}

// Track resolves podUID's current leaf cgroup ID(s) and adds them to the
// map. Returns the resolved IDs (one per container in the pod). Safe to call
// repeatedly (e.g. on a poll loop) as pods are admitted to the node.
func (r *Resolver) Track(podUID string) ([]uint64, error) {
	ids, err := PodLeafCgroupIDs(r.cgroupRoot, podUID)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	// Track is also the refresh path, so the pod's leaf set can legitimately
	// shrink (for example, the workload container exits before its pause
	// sandbox is torn down). Remove reverse mappings for the prior snapshot
	// before installing the new one. The ownership check is essential for
	// cgroup-ID reuse: another pod may already have claimed an old numeric ID,
	// in which case refreshing this pod must not delete the new owner's entry.
	for _, id := range r.uidToCgroups[podUID] {
		if owner, ok := r.cgroupToUID[id]; ok && owner == podUID {
			delete(r.cgroupToUID, id)
		}
	}
	r.uidToCgroups[podUID] = ids
	for _, id := range ids {
		r.cgroupToUID[id] = podUID
	}
	return ids, nil
}

// Untrack removes podUID from the map (called on pod deletion/revocation, so
// the eBPF policy map entries for its cgroup IDs can be cleaned up promptly
// — see the "persistence of access after revocation" attack scenario in the
// experiment plan). Returns the cgroup IDs that were removed, and whether
// the pod was present.
func (r *Resolver) Untrack(podUID string) ([]uint64, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids, ok := r.uidToCgroups[podUID]
	if !ok {
		return nil, false
	}
	delete(r.uidToCgroups, podUID)
	for _, id := range ids {
		// A numeric cgroup ID can be reused after the old cgroup disappears.
		// Do not erase a reverse mapping that has since been claimed by the
		// replacement pod.
		if owner, stillTracked := r.cgroupToUID[id]; stillTracked && owner == podUID {
			delete(r.cgroupToUID, id)
		}
	}
	return ids, true
}

// CgroupIDsFor returns the last-resolved leaf cgroup IDs for podUID, if tracked.
func (r *Resolver) CgroupIDsFor(podUID string) ([]uint64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids, ok := r.uidToCgroups[podUID]
	return ids, ok
}

// PodUIDFor returns the pod UID owning cgroupID, if tracked. This is the
// direction the eBPF hooks actually need at runtime: a cgroup ID observed via
// bpf_get_current_cgroup_id() must resolve back to "whose pod is this" to
// pick the right policy / attribute the right evidence.
func (r *Resolver) PodUIDFor(cgroupID uint64) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	uid, ok := r.cgroupToUID[cgroupID]
	return uid, ok
}

// Len returns the number of currently tracked pods.
func (r *Resolver) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.uidToCgroups)
}
