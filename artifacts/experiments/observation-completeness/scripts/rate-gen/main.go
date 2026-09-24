// Command rate-gen (Task 05, B1) generates a controlled, counted rate of
// file-open operations for a fixed duration, printing the exact number of
// operations it actually attempted (ground truth "generated" count from the
// workload's own perspective) so the experiment can compute
// observed/attempted at increasing offered rates. Pure stdlib, no go.mod
// needed. Uses plain open()/close() in a paced loop -- fast enough in a
// single process to reach the requested rates without subprocess-spawn
// overhead dominating.
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintln(os.Stderr, "usage: rate-gen <target-path> <rate-per-sec> <duration-seconds>")
		os.Exit(2)
	}
	target := os.Args[1]
	rate, err := strconv.Atoi(os.Args[2])
	if err != nil || rate <= 0 {
		fmt.Fprintln(os.Stderr, "invalid rate:", os.Args[2])
		os.Exit(2)
	}
	durationSec, err := strconv.Atoi(os.Args[3])
	if err != nil || durationSec <= 0 {
		fmt.Fprintln(os.Stderr, "invalid duration:", os.Args[3])
		os.Exit(2)
	}

	interval := time.Second / time.Duration(rate)
	deadline := time.Now().Add(time.Duration(durationSec) * time.Second)
	var attempted, failed int64
	next := time.Now()

	for time.Now().Before(deadline) {
		fd, err := syscall.Open(target, syscall.O_RDONLY, 0)
		attempted++
		if err != nil {
			failed++
		} else {
			syscall.Close(fd)
		}
		next = next.Add(interval)
		if sleep := time.Until(next); sleep > 0 {
			time.Sleep(sleep)
		}
	}

	fmt.Printf("RATE_GEN_RESULT attempted=%d failed=%d target_rate=%d duration_seconds=%d\n",
		attempted, failed, rate, durationSec)
}
