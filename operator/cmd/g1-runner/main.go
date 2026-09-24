// Command g1-runner is the pod's own entrypoint process for Task 10's G1
// safe deny/allow tests. It must run INSIDE the same process the
// container starts with (not be invoked later via `kubectl exec`):
// empirically, once a cgroup's RuntimeSecurityPolicy is enforce-mode with
// a restrictive default-deny policy, `kubectl exec`'s own OCI runtime
// attach path (which itself needs to open several /proc files inside the
// container's namespaces to set up the new attached process) gets denied
// by the very same file_open LSM hook this experiment is testing --
// confirmed directly ("open /proc/sys/kernel/cap_last_cap: operation not
// permitted" from `kubectl exec`, not from this program). The container's
// OWN original process is unaffected (already running before the policy
// tightens), so this binary IS that original process, looping through all
// G1 conditions internally and printing one final JSON line at the end --
// same single-line-JSON-on-stdout convention as scale-generator/
// perf-workload, so the harness's already-hardened last-line capture
// logic works unchanged.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

type probeResult struct {
	Op                 string `json:"op"`
	Condition          string `json:"condition"` // "allow" or "deny"
	Rep                int    `json:"rep"`
	Target             string `json:"target"`
	Success            bool   `json:"success"`
	Errno              string `json:"errno,omitempty"`
	ErrnoIsEPERM       bool   `json:"errno_is_eperm"`
	SideEffectObserved bool   `json:"side_effect_observed"`
	RawError           string `json:"raw_error,omitempty"`
}

func errnoOf(err error) (syscall.Errno, bool) {
	for err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			return errno, true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return 0, false
		}
		err = u.Unwrap()
	}
	return 0, false
}

func probeExec(target string) (bool, string, bool, bool, string) {
	cmd := exec.Command(target)
	// Explicitly inherit this process's own already-open stdio FDs
	// rather than leaving Stdin/Stdout/Stderr nil: Go's os/exec opens
	// /dev/null for any nil stream, and that open() is itself subject to
	// the same file_open LSM hook this experiment tests -- under a
	// restrictive deny-by-default device policy (empirically discovered
	// running this exact test), the /dev/null open was denied and masked
	// whether the REQUESTED target's own execve() was allowed/denied.
	// Inheriting already-open FDs via fork requires no new open() call.
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return true, "", false, true, ""
	}
	errno, ok := errnoOf(err)
	if !ok {
		return false, "", false, false, err.Error()
	}
	return false, errno.Error(), errno == syscall.EPERM, false, err.Error()
}

func probeFileOpen(target string) (bool, string, bool, bool, string) {
	f, err := os.Open(target)
	if err != nil {
		errno, ok := errnoOf(err)
		if !ok {
			return false, "", false, false, err.Error()
		}
		return false, errno.Error(), errno == syscall.EPERM, false, err.Error()
	}
	defer f.Close()
	return true, "", false, true, ""
}

func probeConnect(target string) (bool, string, bool, bool, string) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false, "", false, false, "socket: " + err.Error()
	}
	defer syscall.Close(fd)

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return false, "", false, false, "parse target: " + err.Error()
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false, "", false, false, "parse port: " + err.Error()
	}
	parsedIP := net.ParseIP(host).To4()
	if parsedIP == nil {
		return false, "", false, false, "parse ip: not IPv4: " + host
	}
	var ip [4]byte
	copy(ip[:], parsedIP)

	err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: port, Addr: ip})
	if err == nil {
		return true, "", false, true, ""
	}
	if errno, ok := err.(syscall.Errno); ok {
		return false, errno.Error(), errno == syscall.EPERM, false, err.Error()
	}
	return false, "", false, false, err.Error()
}

func run(op, condition, target string, rep int) probeResult {
	var success, sideEffect, isEPERM bool
	var errno, rawErr string
	switch op {
	case "exec":
		success, errno, isEPERM, sideEffect, rawErr = probeExec(target)
	case "file":
		success, errno, isEPERM, sideEffect, rawErr = probeFileOpen(target)
	case "network":
		success, errno, isEPERM, sideEffect, rawErr = probeConnect(target)
	}
	return probeResult{
		Op: op, Condition: condition, Rep: rep, Target: target,
		Success: success, Errno: errno, ErrnoIsEPERM: isEPERM,
		SideEffectObserved: sideEffect, RawError: rawErr,
	}
}

func main() {
	bootstrapWait := flag.Duration("bootstrap-wait", 25*time.Second, "wait before starting tests, giving the harness time to mint the decision and patch the policy to enforce mode")
	execAllow := flag.String("exec-allow-target", "/bin/true", "")
	execDeny := flag.String("exec-deny-target", "/bin/false", "")
	fileAllow := flag.String("file-allow-target", "/tmp/allowed-testfile", "")
	fileDeny := flag.String("file-deny-target", "/etc/hostname", "")
	netAllow := flag.String("network-allow-target", "127.0.0.1:9999", "")
	netDeny := flag.String("network-deny-target", "127.0.0.1:8888", "")
	repsExec := flag.Int("reps-exec", 30, "")
	repsFile := flag.Int("reps-file", 15, "")
	repsNetwork := flag.Int("reps-network", 15, "")
	flag.Parse()

	time.Sleep(*bootstrapWait)

	// Diagnostic warm-up: repeatedly probe the exec-allow target (logged
	// to stderr, not part of the final JSON result) until it succeeds or
	// a hard cap is reached, instead of trusting a single fixed
	// bootstrap-wait. Two prior runs at 25s and 60s bootstrap-wait showed
	// inconsistent results (25s: allow succeeded; 60s: allow denied) even
	// though the RuntimeSecurityPolicy object's spec was confirmed
	// unchanged and correct throughout -- pointing at eBPF map
	// propagation/consistency timing this warm-up makes directly
	// observable instead of guessed at.
	warmupDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(warmupDeadline) {
		ok, errno, isEPERM, _, rawErr := probeExec(*execAllow)
		fmt.Fprintf(os.Stderr, "warmup exec-allow probe: success=%v errno=%q eperm=%v raw=%q\n", ok, errno, isEPERM, rawErr)
		if ok {
			break
		}
		time.Sleep(3 * time.Second)
	}

	// The file-allow target must be created by THIS process (the one the
	// container started with), matching AllowedPathPrefixes -- see
	// package comment for why kubectl exec cannot be used for this.
	if f, err := os.Create(*fileAllow); err == nil {
		f.WriteString("g1 allow marker\n")
		f.Close()
	} else {
		fmt.Fprintf(os.Stderr, "warning: could not create file-allow target %s: %v\n", *fileAllow, err)
	}

	var results []probeResult
	for i := 1; i <= *repsExec; i++ {
		results = append(results, run("exec", "allow", *execAllow, i))
		results = append(results, run("exec", "deny", *execDeny, i))
	}
	for i := 1; i <= *repsFile; i++ {
		results = append(results, run("file", "allow", *fileAllow, i))
		results = append(results, run("file", "deny", *fileDeny, i))
	}
	for i := 1; i <= *repsNetwork; i++ {
		results = append(results, run("network", "allow", *netAllow, i))
		results = append(results, run("network", "deny", *netDeny, i))
	}

	json.NewEncoder(os.Stdout).Encode(results)
}
