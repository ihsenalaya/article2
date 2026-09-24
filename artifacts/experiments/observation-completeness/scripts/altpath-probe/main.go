// Command altpath-probe (Task 05, B2) deliberately invokes the "alternate
// kernel path" syscall variants the experiment protocol asks about --
// openat2(2) (not open/openat) and execveat(2) (not execve) -- via raw
// syscall numbers, so this experiment can determine empirically whether
// RuntimeGuard's audit-mode tracepoint hooks (which only attach to
// sys_enter_execve/open/openat, per ebpf-agent/internal/loader/loader.go)
// actually observe these paths or silently miss them. Pure stdlib, no
// external deps, so it needs no go.mod of its own -- built with
// `go build -o altpath-probe main.go`.
//
// Usage: altpath-probe <mode>
//
//	mode = openat2   : open a target file via raw openat2(2)
//	mode = execveat  : exec a target binary via raw execveat(2)
//	mode = openat    : open the same file via ordinary openat(2) (control)
//	mode = execve    : exec the same binary via ordinary execve(2) (control)
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// x86_64 syscall numbers (from asm/unistd_64.h) -- hardcoded because pulling
// in golang.org/x/sys/unix just for these two constants is unnecessary for
// a single-purpose probe binary.
const (
	sysOpenat2  = 437
	sysExecveat = 322
)

// atFDCWD is Linux's AT_FDCWD (fcntl.h) -- not exported by the stdlib
// syscall package. A package-level var, not a const: Go disallows
// converting a negative CONSTANT to uintptr even when explicitly typed
// (representability is still checked at compile time for constants), but a
// plain runtime value conversion of a variable wraps via two's complement
// exactly as the kernel ABI expects.
var atFDCWD int32 = -100

// open_how, per openat2(2) -- must match the kernel ABI exactly.
type openHow struct {
	flags   uint64
	mode    uint64
	resolve uint64
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: altpath-probe <openat2|execveat|openat|execve> <target-path>")
		os.Exit(2)
	}
	mode, target := os.Args[1], os.Args[2]

	switch mode {
	case "openat2":
		how := openHow{flags: syscall.O_RDONLY}
		pathPtr, err := syscall.BytePtrFromString(target)
		if err != nil {
			fmt.Fprintln(os.Stderr, "path:", err)
			os.Exit(1)
		}
		fd, _, errno := syscall.Syscall6(sysOpenat2, uintptr(atFDCWD),
			uintptr(unsafe.Pointer(pathPtr)), uintptr(unsafe.Pointer(&how)), unsafe.Sizeof(how), 0, 0)
		if errno != 0 {
			fmt.Fprintf(os.Stderr, "openat2(%s) failed: errno=%d\n", target, errno)
			os.Exit(1)
		}
		syscall.Close(int(fd))
		fmt.Printf("openat2(%s) succeeded, fd=%d\n", target, fd)

	case "openat":
		fd, err := syscall.Openat(int(atFDCWD), target, syscall.O_RDONLY, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "openat(%s) failed: %v\n", target, err)
			os.Exit(1)
		}
		syscall.Close(fd)
		fmt.Printf("openat(%s) succeeded, fd=%d\n", target, fd)

	case "execveat":
		dirFd, err := syscall.Open(target, syscall.O_RDONLY, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "open target for execveat:", err)
			os.Exit(1)
		}
		emptyPath, _ := syscall.BytePtrFromString("")
		argv0, _ := syscall.BytePtrFromString(target)
		argvPtrs := []*byte{argv0, nil}
		envp := []*byte{nil}
		_, _, errno := syscall.Syscall6(sysExecveat, uintptr(dirFd), uintptr(unsafe.Pointer(emptyPath)),
			uintptr(unsafe.Pointer(&argvPtrs[0])), uintptr(unsafe.Pointer(&envp[0])), uintptr(0x1000) /*AT_EMPTY_PATH*/, 0)
		// execveat only returns on failure (success replaces this process).
		fmt.Fprintf(os.Stderr, "execveat(%s) failed to replace process: errno=%d\n", target, errno)
		os.Exit(1)

	case "execve":
		err := syscall.Exec(target, []string{target}, os.Environ())
		fmt.Fprintf(os.Stderr, "execve(%s) failed to replace process: %v\n", target, err)
		os.Exit(1)

	default:
		fmt.Fprintln(os.Stderr, "unknown mode:", mode)
		os.Exit(2)
	}
}
