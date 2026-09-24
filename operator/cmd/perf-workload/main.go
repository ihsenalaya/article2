// Command perf-workload runs a controlled, fixed-count loop of one
// monitored operation type (exec, file-open, or network-connect) and
// reports precise wall-clock and CPU-time cost for Task 09 (Experiment F,
// event-dependent performance cost). It has no Kubernetes API dependency
// at all -- whether a run is "ON" (RuntimeGuard actively tracking this
// pod's cgroup) or "OFF" (untracked) is controlled entirely by the
// harness deciding whether to mint/apply a RuntimeSecurityPolicy for this
// pod before invoking this binary (see
// artifacts/experiments/performance/scripts/lib.sh), not by anything
// this binary does.
//
// CPU time is read via getrusage(RUSAGE_SELF) and getrusage(RUSAGE_CHILDREN)
// deltas, summed: the exec operation's traced syscall (execve) runs in a
// forked child's context, so RUSAGE_SELF alone would miss it, while
// file/network operations run entirely in this process's own context, so
// RUSAGE_CHILDREN stays ~0 for those -- summing both is correct and
// uniform across operation types without per-op special-casing.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

func rusageDelta(kind int) (userSec, sysSec float64, err error) {
	var ru syscall.Rusage
	if err = syscall.Getrusage(kind, &ru); err != nil {
		return 0, 0, err
	}
	return float64(ru.Utime.Sec) + float64(ru.Utime.Usec)/1e6,
		float64(ru.Stime.Sec) + float64(ru.Stime.Usec)/1e6, nil
}

func runOnce(op string) error {
	switch op {
	case "exec":
		// Explicitly inherit the runner's own already-open FDs. With these
		// left nil, Go's os/exec opens /dev/null separately for each of
		// Stdin/Stdout/Stderr before forking -- real openat() syscalls
		// inside THIS pod's own monitored cgroup, which the audit-mode
		// trace_open/trace_openat tracepoints record as extra FILE_OPEN
		// events on top of the one EXEC event actually under test. Found
		// via Task 09's f3-event-drop-check anomaly (exec's
		// incorporated_count was ~19x n; file/network, which never call
		// exec.Command, were clean ~1x) -- the same root cause already
		// identified and fixed for cmd/g1-runner in Task 10.
		cmd := exec.Command("/bin/true")
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	case "file":
		f, err := os.Open("/etc/hostname")
		if err != nil {
			return err
		}
		var buf [64]byte
		_, _ = f.Read(buf[:])
		return f.Close()
	case "network":
		conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 500*time.Millisecond)
		if err != nil {
			return err
		}
		return conn.Close()
	default:
		return fmt.Errorf("unknown op %q", op)
	}
}

type result struct {
	Op              string  `json:"op"`
	N               int     `json:"n"`
	Worker          int     `json:"worker"`
	NCompleted      int     `json:"n_completed"`
	NErrors         int     `json:"n_errors"`
	WallSeconds     float64 `json:"wall_seconds"`
	CPUUserSeconds  float64 `json:"cpu_user_seconds"`
	CPUSysSeconds   float64 `json:"cpu_sys_seconds"`
	CPUTotalSeconds float64 `json:"cpu_total_seconds"`
	OpsPerSecond    float64 `json:"ops_per_second"`
	USecPerOp       float64 `json:"usec_per_op_cpu_total"`
	// MaxRSSKBBefore/After (Task 12 follow-up, closing a documented gap in
	// F3's own metric list): getrusage(RUSAGE_SELF).Maxrss is a
	// HIGH-WATER-MARK, not an instantaneous reading, so "before" is not
	// actually meaningful on its own (it reflects everything since process
	// start, same as "after" minus growth during this specific loop) --
	// both are reported anyway, plus the delta, so a reader can see the
	// growth attributable to running N operations, not just an opaque
	// final number. On Linux, Getrusage's Maxrss is already in KB (unlike
	// macOS/BSD, where it is bytes -- this binary only ever runs in the
	// campaign's Linux containers, so no platform branch is needed).
	MaxRSSKBBefore int64 `json:"max_rss_kb_before"`
	MaxRSSKBAfter  int64 `json:"max_rss_kb_after"`
	MaxRSSKBDelta  int64 `json:"max_rss_kb_delta"`
}

func maxRSSKB() int64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return -1
	}
	return ru.Maxrss
}

func runWorker(op string, n int, workerIdx int) result {
	selfU0, selfS0, _ := rusageDelta(syscall.RUSAGE_SELF)
	childU0, childS0, _ := rusageDelta(syscall.RUSAGE_CHILDREN)
	rssBefore := maxRSSKB()
	t0 := time.Now()

	errs := 0
	for i := 0; i < n; i++ {
		if err := runOnce(op); err != nil {
			errs++
		}
	}

	wall := time.Since(t0).Seconds()
	selfU1, selfS1, _ := rusageDelta(syscall.RUSAGE_SELF)
	childU1, childS1, _ := rusageDelta(syscall.RUSAGE_CHILDREN)
	rssAfter := maxRSSKB()

	cpuUser := (selfU1 - selfU0) + (childU1 - childU0)
	cpuSys := (selfS1 - selfS0) + (childS1 - childS0)
	cpuTotal := cpuUser + cpuSys

	r := result{
		Op: op, N: n, Worker: workerIdx, NCompleted: n - errs, NErrors: errs,
		WallSeconds: wall, CPUUserSeconds: cpuUser, CPUSysSeconds: cpuSys,
		CPUTotalSeconds: cpuTotal,
		MaxRSSKBBefore:  rssBefore,
		MaxRSSKBAfter:   rssAfter,
		MaxRSSKBDelta:   rssAfter - rssBefore,
	}
	if wall > 0 {
		r.OpsPerSecond = float64(n) / wall
	}
	if n > 0 {
		r.USecPerOp = (cpuTotal * 1e6) / float64(n)
	}
	return r
}

func main() {
	op := flag.String("op", "exec", "exec|file|network")
	n := flag.Int("n", 2000, "iteration count per worker")
	concurrency := flag.Int("concurrency", 1, "number of concurrent worker goroutines (F4 rate curve; each spawns its own subprocess for exec, so this drives genuine achieved concurrency, not sleep-throttling)")
	flag.Parse()

	if *concurrency <= 1 {
		out := runWorker(*op, *n, 0)
		json.NewEncoder(os.Stdout).Encode(out)
		return
	}

	results := make([]result, *concurrency)
	var wg sync.WaitGroup
	t0 := time.Now()
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = runWorker(*op, *n, idx)
		}(w)
	}
	wg.Wait()
	wallTotal := time.Since(t0).Seconds()

	agg := struct {
		Op              string   `json:"op"`
		N               int      `json:"n"`
		Concurrency     int      `json:"concurrency"`
		TotalOps        int      `json:"total_ops"`
		TotalErrors     int      `json:"total_errors"`
		WallSeconds     float64  `json:"wall_seconds"`
		CPUTotalSeconds float64  `json:"cpu_total_seconds"`
		AggOpsPerSecond float64  `json:"agg_ops_per_second"`
		Workers         []result `json:"workers"`
	}{Op: *op, N: *n, Concurrency: *concurrency, WallSeconds: wallTotal}

	for _, r := range results {
		agg.TotalOps += r.NCompleted
		agg.TotalErrors += r.NErrors
		agg.CPUTotalSeconds += r.CPUTotalSeconds
		agg.Workers = append(agg.Workers, r)
	}
	if wallTotal > 0 {
		agg.AggOpsPerSecond = float64(agg.TotalOps) / wallTotal
	}
	json.NewEncoder(os.Stdout).Encode(agg)
}
