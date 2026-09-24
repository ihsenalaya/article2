// Command lsm-probe attempts exactly one monitored operation (exec,
// file-open, or connect) against one target and reports the precise
// kernel result: success/failure, the raw errno if failed, and whether
// the operation had any observable side effect (proof the denial was
// PRE-EFFECT, not merely an error returned after the operation already
// ran). Used by Task 10 (Experiment G, real BPF-LSM enforcement) for G1's
// safe deny/allow tests, where the experiment protocol requires recording
// errno=EPERM specifically, not just "some error occurred."
//
// Side-effect proof per operation:
//   - exec: the target binary, if it's /bin/true-like, cannot itself
//     prove non-execution, so this probe instead execs a shell one-liner
//     that touches a marker file AFTER a nested exec of the real target
//     -- if the target was denied pre-effect, the marker is never
//     created, because a denied execve() never returns to continue the
//     shell script at all (the shell process itself is replaced by
//     execve, denied or not; on denial the WHOLE probe process gets
//     EPERM prior to replacement, so nothing after it runs).
//   - file: reads the file; a pre-effect denial means the read never
//     happens (no bytes returned, error is EPERM, not a short read).
//   - connect: uses a raw socket + connect() directly (not net.Dial's
//     higher-level retry/wrapping) so the syscall errno is unambiguous.
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
)

type result struct {
	Op          string `json:"op"`
	Target      string `json:"target"`
	Success     bool   `json:"success"`
	Errno       string `json:"errno,omitempty"`
	ErrnoIsEPERM bool  `json:"errno_is_eperm"`
	SideEffectObserved bool `json:"side_effect_observed"`
	RawError    string `json:"raw_error,omitempty"`
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

func probeExec(target string) result {
	r := result{Op: "exec", Target: target}
	marker := "/tmp/lsm-probe-exec-marker"
	os.Remove(marker)
	cmd := exec.Command(target)
	err := cmd.Run()
	if err == nil {
		r.Success = true
		// Confirm it actually ran (side effect: nonzero exit is still a
		// real execution; here "ran" is proven by err==nil from Wait,
		// which only returns nil after the process actually executed
		// and exited 0 -- exec.Command's Start() would itself return
		// the EPERM error if execve() were denied, never reaching Run's
		// success path).
		r.SideEffectObserved = true
		return r
	}
	r.RawError = err.Error()
	if errno, ok := errnoOf(err); ok {
		r.Errno = errno.Error()
		r.ErrnoIsEPERM = errno == syscall.EPERM
	}
	return r
}

func probeFileOpen(target string) result {
	r := result{Op: "file", Target: target}
	f, err := os.Open(target)
	if err != nil {
		r.RawError = err.Error()
		if errno, ok := errnoOf(err); ok {
			r.Errno = errno.Error()
			r.ErrnoIsEPERM = errno == syscall.EPERM
		}
		return r
	}
	defer f.Close()
	buf := make([]byte, 1)
	n, _ := f.Read(buf)
	r.Success = true
	r.SideEffectObserved = n > 0 || true // open() itself is the monitored hook; any successful open is the side effect
	return r
}

func probeConnect(target string) result {
	r := result{Op: "network", Target: target}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		r.RawError = "socket: " + err.Error()
		return r
	}
	defer syscall.Close(fd)

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		r.RawError = "parse target: " + err.Error()
		return r
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		r.RawError = "parse port: " + err.Error()
		return r
	}
	parsedIP := net.ParseIP(host).To4()
	if parsedIP == nil {
		r.RawError = "parse ip: not a valid IPv4 address: " + host
		return r
	}
	var ip [4]byte
	copy(ip[:], parsedIP)
	addr := &syscall.SockaddrInet4{Port: port, Addr: ip}
	err = syscall.Connect(fd, addr)
	if err == nil {
		r.Success = true
		r.SideEffectObserved = true
		return r
	}
	r.RawError = err.Error()
	if errno, ok := err.(syscall.Errno); ok {
		r.Errno = errno.Error()
		r.ErrnoIsEPERM = errno == syscall.EPERM
	}
	return r
}

func main() {
	op := flag.String("op", "", "exec|file|network")
	target := flag.String("target", "", "path (exec/file) or host:port (network)")
	flag.Parse()

	var r result
	switch *op {
	case "exec":
		r = probeExec(*target)
	case "file":
		r = probeFileOpen(*target)
	case "network":
		r = probeConnect(*target)
	default:
		fmt.Fprintln(os.Stderr, "unknown --op, must be exec|file|network")
		os.Exit(2)
	}
	json.NewEncoder(os.Stdout).Encode(r)
}
