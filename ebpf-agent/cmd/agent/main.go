// Command agent is the Runtime Guard node eBPF agent entrypoint: it loads
// the compiled BPF programs (audit-only tracepoints or enforce-capable LSM
// hooks, depending on whether this node's kernel has BPF-LSM active),
// resolves RuntimeSecurityPolicy objects targeting pods on this node to
// their cgroup IDs, writes the corresponding BPF policy maps, and emits
// signed RuntimePlacementEvidence.
//
// Scope note (Phase 4): reconciliation here is a simple poll loop, not a
// full controller-runtime manager with watches/leader election. The agent's
// value is the eBPF programs and the cgroup/hash/signing logic — all of
// which have real unit tests in their own packages — not sophisticated
// Kubernetes controller machinery. A watch-based reconciler is a reasonable
// future refinement, not required for this phase's or Phase 5's kind
// validation.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	"github.com/ihsenalaya/runtime-guard-operator/pkg/evidence"

	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/bpfobjs"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/cgroupmap"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/loader"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/lsmdetect"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/policy"
	"github.com/ihsenalaya/runtime-guard-ebpf-agent/internal/trustverify"
)

// monotonicRawNs reads CLOCK_MONOTONIC_RAW, the node-local userspace clock
// this campaign uses for t_p (see artifacts/timing/timestamp-semantics.md).
// It is only ever compared against another CLOCK_MONOTONIC_RAW reading on
// the SAME node -- never across nodes, and never directly against
// bpf_ktime_get_ns() readings without accounting for the two clocks' small
// documented skew (both are monotonic-since-boot, but CLOCK_MONOTONIC_RAW is
// not NTP-frequency-adjusted while the clock bpf_ktime_get_ns() reads from
// is; see the timestamp-semantics doc for the measured magnitude).
func monotonicRawNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts); err != nil {
		return 0
	}
	return unix.TimespecToNsec(ts)
}

const (
	enforcementReadyConditionType = "EnforcementReady"
	enforcementReadyReason        = "PolicyApplied"
	enforcementReadyAnnotation    = "runtime-guard.ai/enforcement-ready-at"
	enforcementPolicyAnnotation   = "runtime-guard.ai/enforcement-policy"

	// injectReadyDelayAnnotation is a Task 04-A2 test-harness-only pod
	// annotation (value: integer milliseconds) that artificially delays this
	// specific pod's first policy application. See its use in reconcileOnce.
	injectReadyDelayAnnotation = "experiment.article2.io/inject-ready-delay-ms"
)

func main() {
	// BENCHMARK-ONLY (see common.h's BENCH_MODE_* doc comment and
	// artifacts/bpf_lsm_enforcement_overhead/): the agent's own container
	// image is distroless (no shell, no coreutils), so `kubectl exec <pod>
	// -- sh -c '...'` cannot write/poll the benchmark control files from
	// outside. This binary doubles as its own control-client: `kubectl exec
	// <agent-pod> -- /agent bench-cmd "<command>"` writes directly to the
	// same control dir the running agent process's benchmarkControlLoop
	// polls, waits for its ack file, prints it, and exits -- before any of
	// the normal flag parsing/server startup below ever runs. Only reachable
	// by deliberately invoking this exact subcommand; the normal
	// `/agent --node-name=... ...` entrypoint is completely unaffected.
	if len(os.Args) > 1 && os.Args[1] == "bench-cmd" {
		os.Exit(runBenchmarkCommandClient(os.Args[2:]))
	}

	var (
		nodeName                 = flag.String("node-name", os.Getenv("NODE_NAME"), "Kubernetes node name this agent runs on (required, usually Downward API spec.nodeName)")
		cgroupRoot               = flag.String("cgroup-root", envOrDefault("CGROUP_ROOT", "/sys/fs/cgroup"), "cgroup v2 root mount point")
		lsmPath                  = flag.String("lsm-path", envOrDefault("LSM_PATH", lsmdetect.DefaultLSMPath), "path to the active LSM list (/sys/kernel/security/lsm)")
		pollInterval             = flag.Duration("poll-interval", 5*time.Second, "how often to re-list RuntimeSecurityPolicy objects and refresh maps")
		evidenceInterval         = flag.Duration("evidence-interval", 30*time.Second, "how often to emit signed RuntimePlacementEvidence per tracked pod")
		agentImageDigest         = flag.String("agent-image-digest", os.Getenv("AGENT_IMAGE_DIGEST"), "this agent's own running image digest (repo@sha256:...), stamped into evidence for the Janus-style integrity chain")
		signingKeyHex            = flag.String("signing-key-hex", os.Getenv("AGENT_SIGNING_KEY_HEX"), "hex-encoded Ed25519 private key seed used to sign RuntimePlacementEvidence")
		bpfLockEnabled           = flag.Bool("bpf-lock-enabled", os.Getenv("BPF_LOCK_ENABLED") == "true", "engage the BPF-lock LSM hook after loading (only takes effect in enforce mode)")
		evidenceNamespace        = flag.String("evidence-namespace", envOrDefault("EVIDENCE_NAMESPACE", "aiops-system"), "namespace to create RuntimePlacementEvidence objects in")
		watchRevocation          = flag.Bool("watch-revocation", os.Getenv("WATCH_REVOCATION") == "true", "Task 06/C2: additionally react to RuntimeSecurityPolicy deletion via a Kubernetes watch (near-instant), instead of relying solely on the --poll-interval ticker. Opt-in -- default (false) preserves the original poll-only behavior (this module's own documented scope decision; see the package doc comment) so this is purely an experimental comparison path, not a production behavior change")
		trustAnchorNamespace     = flag.String("trust-anchor-namespace", envOrDefault("TRUST_ANCHOR_NAMESPACE", "aiops-system"), "Task 11: namespace of the ConfigMap holding the scheduler's Ed25519 public key, for worker-side D->P validation")
		trustAnchorConfigMapName = flag.String("trust-anchor-configmap", envOrDefault("TRUST_ANCHOR_CONFIGMAP_NAME", "attestation-scheduler-public-key"), "Task 11: name of the trust-anchor ConfigMap (same one the operator's own controller reads)")
		trustAnchorConfigMapKey  = flag.String("trust-anchor-configmap-key", envOrDefault("TRUST_ANCHOR_CONFIGMAP_KEY", "publicKeyHex"), "Task 11: key within the trust-anchor ConfigMap holding the hex-encoded public key")
		workerTrustValidation    = flag.Bool("worker-trust-validation", os.Getenv("WORKER_TRUST_VALIDATION") != "false", "Task 11: independently verify each RuntimeSecurityPolicy against its source AIPlacementDecision (signature, freshness, anti-replay, hash(P_received)==hash(derive(D))) before trusting it; policies that fail get a safe deny-all plan instead of their own (possibly tampered) rules. Default true; --worker-trust-validation=false reproduces the pre-Task-11 behavior for comparison")
		trustAnchorPinPath       = flag.String("trust-anchor-pin-path", envOrDefault("TRUST_ANCHOR_PIN_PATH", "/var/lib/runtime-guard-agent/trust-anchor.pin"), "Task 12 follow-up: local, node-persistent file used to Trust-On-First-Use-pin the scheduler's public key, so an unannounced trust-anchor-ConfigMap change (compromise or unauthorized rotation) is detected and refused instead of silently trusted. See trustverify.LoadTrustAnchorTOFU's doc comment for exactly what this does and does not defend against")
		replayLedgerPath         = flag.String("replay-ledger-path", envOrDefault("REPLAY_LEDGER_PATH", "/var/lib/runtime-guard-agent/replay-ledger.json"), "Task 12 follow-up: local, node-persistent file used to persist the anti-replay ledger across agent restarts on the same node (previously in-memory only, reset on every restart)")
		benchmarkModeEnabled     = flag.Bool("benchmark-mode-enabled", os.Getenv("BENCHMARK_MODE_ENABLED") == "true", "BENCHMARK-ONLY (artifacts/bpf_lsm_enforcement_overhead/): opt-in local-filesystem control surface letting the benchmark orchestration detach/reattach one LSM hook or set a cgroup's benchmark_mode, via `kubectl exec` writing to --benchmark-control-dir. Default false: no effect on any production deployment")
		benchmarkControlDir      = flag.String("benchmark-control-dir", envOrDefault("BENCHMARK_CONTROL_DIR", "/tmp/benchctl"), "BENCHMARK-ONLY: directory the benchmark control loop polls for commands (only read/created when --benchmark-mode-enabled)")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	if *nodeName == "" {
		logger.Error("node-name is required (set NODE_NAME via Downward API)")
		os.Exit(1)
	}
	if *agentImageDigest == "" {
		logger.Error("agent-image-digest is required (Janus-style agent integrity requirement: the agent must know, and report, its own running digest)")
		os.Exit(1)
	}
	if *signingKeyHex == "" {
		logger.Error("signing-key-hex is required to sign RuntimePlacementEvidence")
		os.Exit(1)
	}
	signingKey, err := platformcrypto.PrivKeyFromHex(*signingKeyHex)
	if err != nil {
		logger.Error("invalid signing key", "error", err)
		os.Exit(1)
	}

	mode := lsmdetect.DetermineMode(*lsmPath)
	logger.Info("determined enforcement mode", "mode", mode, "lsmPath", *lsmPath)

	bpfAgent, err := loader.Load(mode)
	if err != nil {
		logger.Error("failed to load BPF programs", "error", err)
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			// The default %v/Error() output truncates to a short tail —
			// print the complete verifier log so a rejection is actually
			// diagnosable instead of guessed at. See EXPERIMENTS_LOG.md
			// Phase 4 for why this was added (several verifier rejections
			// needed the full trace to root-cause, not the summary).
			fmt.Printf("=== full verifier log ===\n%+v\n=== end verifier log ===\n", verr)
		}
		os.Exit(1)
	}
	defer bpfAgent.Close()

	if *bpfLockEnabled && mode == lsmdetect.ModeEnforce {
		if err := bpfAgent.EnableBPFLock(); err != nil {
			logger.Error("failed to engage BPF-lock", "error", err)
			os.Exit(1)
		}
		logger.Info("BPF-lock engaged: further BPF program loads on this node will be denied")
	} else if *bpfLockEnabled {
		logger.Warn("bpf-lock-enabled was requested but mode is audit (BPF-LSM inactive) — BPF-lock requires enforce mode, skipping")
	}

	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		logger.Error("register scheme", "error", err)
		os.Exit(1)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		logger.Error("register scheme", "error", err)
		os.Exit(1)
	}
	restConfig, err := config.GetConfig()
	if err != nil {
		logger.Error("get kubeconfig", "error", err)
		os.Exit(1)
	}
	k8sClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		logger.Error("create Kubernetes client", "error", err)
		os.Exit(1)
	}
	var watchClient client.WithWatch
	if *watchRevocation {
		watchClient, err = client.NewWithWatch(restConfig, client.Options{Scheme: scheme})
		if err != nil {
			logger.Error("create watch-capable Kubernetes client", "error", err)
			os.Exit(1)
		}
	}

	acc := newAccumulator()
	go func() {
		if err := bpfAgent.ReadEvents(acc.handle); err != nil {
			logger.Error("ring buffer reader stopped", "error", err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tracker := newPodTracker(*cgroupRoot)

	monitorEpoch := newMonitorEpoch()
	digest := hookSetDigest(mode, *bpfLockEnabled && mode == lsmdetect.ModeEnforce)
	logger.Info("monitor identity", "monitorEpoch", monitorEpoch, "hookSetDigest", digest)

	ledger, err := trustverify.NewReplayLedgerPersistent(*replayLedgerPath)
	if err != nil {
		// Fail-safe direction: an unreadable/corrupt persisted ledger must
		// not silently fall back to a fresh (i.e. weaker) in-memory ledger
		// that has forgotten what it previously rejected -- that would
		// quietly reopen the exact replay window persistence exists to
		// close. Refuse to start instead, the same way a bad signing-key
		// or missing node-name already does above.
		logger.Error("load persistent replay ledger", "path", *replayLedgerPath, "error", err)
		os.Exit(1)
	}
	trust := trustConfig{
		enabled:          *workerTrustValidation,
		namespace:        *trustAnchorNamespace,
		cmName:           *trustAnchorConfigMapName,
		cmKey:            *trustAnchorConfigMapKey,
		agentImageDigest: *agentImageDigest,
		ledger:           ledger,
		pinPath:          *trustAnchorPinPath,
	}
	logger.Info("Task 11: worker-side D->P trust validation", "enabled", trust.enabled)
	go pollLoop(ctx, logger, k8sClient, bpfAgent, tracker, acc, *nodeName, *pollInterval, mode, trust)
	if watchClient != nil {
		go watchRevocationLoop(ctx, logger, watchClient, tracker, bpfAgent)
	}
	if *benchmarkModeEnabled && mode != lsmdetect.ModeEnforce {
		// Soft skip, not fatal: this flag is set cluster-wide on the
		// DaemonSet (so it also reaches the control-plane node, which this
		// campaign deliberately keeps in audit mode as a within-cluster
		// comparison point) — the benchmark control loop is meaningless
		// without BPF-LSM attached, but a node it doesn't apply to must not
		// crash-loop the whole agent over an opt-in benchmark flag.
		logger.Warn("benchmark-mode-enabled set but this node is in audit mode (BPF-LSM inactive) -- skipping the benchmark control loop here", "mode", mode)
	} else if *benchmarkModeEnabled {
		logger.Warn("BENCHMARK-ONLY control loop enabled -- do not set this flag on a production deployment", "controlDir", *benchmarkControlDir)
		go benchmarkControlLoop(ctx, logger, bpfAgent, *benchmarkControlDir)
	}
	go firstObservationLoop(ctx, logger, k8sClient, tracker, acc)
	evidenceLoop(ctx, logger, k8sClient, tracker, acc, bpfAgent, signingKey, *agentImageDigest, *nodeName, *evidenceNamespace, *evidenceInterval, mode, monitorEpoch, digest)
}

// runBenchmarkCommandClient is BENCHMARK-ONLY, see main()'s doc comment on
// the "bench-cmd" subcommand. Writes args (joined with spaces) to the
// running agent process's control dir and blocks for its ack, printing it to
// stdout. Returns 0 if the ack is exactly "OK", 1 otherwise (including
// timeout) -- so the caller (the benchmark orchestration's `kubectl exec`)
// can check both this process's exit code and stdout.
func runBenchmarkCommandClient(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agent bench-cmd <command...>")
		return 1
	}
	controlDir := envOrDefault("BENCHMARK_CONTROL_DIR", "/tmp/benchctl")
	cmdPath := filepath.Join(controlDir, "cmd")
	ackPath := filepath.Join(controlDir, "ack")
	cmdTmpPath := cmdPath + ".client-tmp"

	_ = os.Remove(ackPath)
	if err := os.WriteFile(cmdTmpPath, []byte(strings.Join(args, " ")), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write command: %v\n", err)
		return 1
	}
	if err := os.Rename(cmdTmpPath, cmdPath); err != nil {
		fmt.Fprintf(os.Stderr, "rename command into place: %v\n", err)
		return 1
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(ackPath)
		if err == nil {
			_ = os.Remove(ackPath)
			fmt.Println(strings.TrimSpace(string(data)))
			if strings.TrimSpace(string(data)) == "OK" {
				return 0
			}
			return 1
		}
		time.Sleep(20 * time.Millisecond)
	}
	fmt.Fprintln(os.Stderr, "timeout waiting for ack (is --benchmark-mode-enabled set on this node's agent?)")
	return 1
}

// benchmarkControlLoop is BENCHMARK-ONLY (see common.h's BENCH_MODE_* doc
// comment and artifacts/bpf_lsm_enforcement_overhead/). Only ever runs when
// --benchmark-mode-enabled is explicitly set (never in production). Polls
// controlDir/cmd for a one-line command written by the benchmark
// orchestration script -- via `kubectl exec` into this agent's own pod,
// never a network listener -- and executes it against the already-running
// bpfAgent, writing the result to controlDir/ack. Supported commands:
//
//	detach <exec|file|connect>
//	reattach <exec|file|connect>
//	setmode <cgroupID> <0|1|2>
func benchmarkControlLoop(ctx context.Context, logger *slog.Logger, bpfAgent *loader.Agent, controlDir string) {
	if err := os.MkdirAll(controlDir, 0o755); err != nil {
		logger.Error("benchmark control: create control dir", "error", err)
		return
	}
	cmdPath := filepath.Join(controlDir, "cmd")
	ackPath := filepath.Join(controlDir, "ack")
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, err := os.ReadFile(cmdPath)
			if err != nil {
				continue // no command pending
			}
			if err := os.Remove(cmdPath); err != nil {
				continue // lost the race to another tick; it will handle this read
			}
			result := executeBenchmarkCommand(bpfAgent, strings.TrimSpace(string(data)))
			// Write-then-rename: the orchestration polls for ackPath to
			// exist, so a partially-written file must never be visible
			// under that name.
			if err := os.WriteFile(ackPath+".tmp", []byte(result), 0o644); err != nil {
				logger.Error("benchmark control: write ack", "error", err)
				continue
			}
			if err := os.Rename(ackPath+".tmp", ackPath); err != nil {
				logger.Error("benchmark control: rename ack", "error", err)
			}
		}
	}
}

func executeBenchmarkCommand(bpfAgent *loader.Agent, cmd string) string {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return "ERROR: empty command"
	}
	switch fields[0] {
	case "detach":
		if len(fields) != 2 {
			return "ERROR: usage: detach <exec|file|connect>"
		}
		if err := bpfAgent.DetachHook(fields[1]); err != nil {
			return "ERROR: " + err.Error()
		}
		return "OK"
	case "reattach":
		if len(fields) != 2 {
			return "ERROR: usage: reattach <exec|file|connect>"
		}
		if err := bpfAgent.ReattachHook(fields[1]); err != nil {
			return "ERROR: " + err.Error()
		}
		return "OK"
	case "setmode":
		if len(fields) != 3 {
			return "ERROR: usage: setmode <cgroupID> <0|1|2>"
		}
		cgroupID, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return "ERROR: invalid cgroup ID: " + err.Error()
		}
		mode, err := strconv.ParseUint(fields[2], 10, 8)
		if err != nil {
			return "ERROR: invalid mode: " + err.Error()
		}
		if err := bpfAgent.SetBenchmarkMode(cgroupID, uint8(mode)); err != nil {
			return "ERROR: " + err.Error()
		}
		return "OK"
	default:
		return "ERROR: unknown command " + fields[0]
	}
}

// newMonitorEpoch generates a fresh identifier for this agent process's
// lifetime (Task 05, B3, Q5). A change in MonitorEpoch between two evidence
// objects for the same pod reveals an agent restart -- a verifier-checkable
// monitor-liveness signal, not a decorative field (experiment protocol: "the
// verifier must actually evaluate them").
func newMonitorEpoch() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing is not a recoverable condition on any
		// supported platform; fall back to a coarse but still-unique-enough
		// (process-start-time) value rather than panicking.
		return fmt.Sprintf("epoch-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// hookSetDigest deterministically hashes which eBPF hook family is attached
// (mode) and whether the BPF-lock defense-in-depth hook is engaged, so a
// verifier can detect a hook-detachment/mode-change event between two
// evidence objects sharing the same MonitorEpoch (Task 05, B3, Q5).
func hookSetDigest(mode lsmdetect.Mode, bpfLockEnabled bool) string {
	var progs []string
	if mode == lsmdetect.ModeEnforce {
		progs = []string{"lsm_exec", "lsm_file_open", "lsm_connect"}
		if bpfLockEnabled {
			progs = append(progs, "lsm_bpf")
		}
	} else {
		progs = []string{"trace_execve", "trace_open", "trace_openat", "trace_connect"}
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("mode=%s;progs=%s", mode, strings.Join(progs, ","))))
	return hex.EncodeToString(sum[:])
}

func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// podTracker remembers which cgroup ID corresponds to which
// (policy namespace/name, pod UID) so the evidence loop and revocation logic
// share the same view the poll loop built.
type podTracker struct {
	resolver *cgroupmap.Resolver

	mu      sync.Mutex
	tracked map[types.NamespacedName]trackedPod // policy NamespacedName -> pod info
}

type trackedPod struct {
	podUID                string
	targetRef             types.NamespacedName // the actual pod's name/namespace — not assumed to equal the policy's own key
	cgroupIDs             []uint64             // one per container in the pod — see cgroupmap's package doc
	lastAppliedGeneration int64                // last RuntimeSecurityPolicy.Generation successfully applied — see the "applied policy" log line
	decisionID            string
	decisionHash          string
	policyHash            string
	policyGeneration      int64
	evidenceSequence      int64
	lastEvidenceDigest    string
	// revokedAt is set once, the first time this pod's policy disappears
	// (deleted, or superseded). The pod stays tracked — and its evidence
	// keeps being emitted — after this point specifically so the
	// "persistence of access after revocation" scenario is observable: a
	// revoked pod's cgroup_configs entry is flipped to deny-by-default (see
	// loader.RevokeCgroup's doc comment on why it updates rather than
	// deletes the entry), and continuing to report its evidence lets that
	// show up as execDenied/etc. actually increasing post-revocation,
	// instead of the evidence object silently freezing at the moment of
	// revocation — which was tried first and made it impossible to tell
	// whether denial-after-revocation was really happening or the object had
	// just stopped being updated. Only once the underlying Pod is actually
	// gone does the tracker finally forget this entry (see reconcileOnce).
	revokedAt *time.Time
	// lastAuthSync is set every poll cycle in which this pod's policy was
	// confirmed still present/live (Task 06/C4-C5), and simply stops being
	// updated once revokedAt is set -- it is never reset backward, so it
	// always reflects "the last time this agent process itself confirmed
	// this decision was still authorized," which is the honest bound on
	// how current an "authorized" claim can be (the agent cannot know
	// about a revocation more recent than its own last successful poll).
	lastAuthSync time.Time
}

func newPodTracker(cgroupRoot string) *podTracker {
	return &podTracker{resolver: cgroupmap.NewResolver(cgroupRoot), tracked: make(map[types.NamespacedName]trackedPod)}
}

// trustConfig bundles Task 11's worker-side D->P validation settings.
// Threaded through pollLoop/reconcileOnce as one value rather than four
// more positional parameters.
type trustConfig struct {
	enabled                  bool
	namespace, cmName, cmKey string
	agentImageDigest         string
	ledger                   *trustverify.ReplayLedger
	pinPath                  string // Task 12 follow-up: TOFU trust-anchor pin file path
}

func pollLoop(ctx context.Context, logger *slog.Logger, c client.Client, bpfAgent *loader.Agent,
	tracker *podTracker, acc *accumulator, nodeName string, interval time.Duration, mode lsmdetect.Mode, trust trustConfig) {
	// time.NewTicker's first tick only fires after a full interval has
	// elapsed, not immediately -- reconcile once synchronously right away so
	// a freshly (re)started agent applies existing policies without waiting
	// out a full --poll-interval first (matters more than it used to now
	// that --poll-interval can be set far longer than its 5s default for
	// artifacts/bpf_lsm_enforcement_overhead's benchmark run, but is a
	// strict improvement at any interval value).
	reconcileOnce(ctx, logger, c, bpfAgent, tracker, acc, nodeName, mode, trust)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			reconcileOnce(ctx, logger, c, bpfAgent, tracker, acc, nodeName, mode, trust)
		}
	}
}

// watchRevocationLoop is Task 06/C2's event-driven alternative to
// pollLoop's fixed-interval revocation detection: it establishes a
// Kubernetes watch on RuntimeSecurityPolicy and reacts to a DELETE event
// for a currently-tracked policy immediately, rather than waiting up to
// --poll-interval for the next re-list to notice the object is gone. Runs
// concurrently with, not instead of, pollLoop -- pollLoop still owns
// policy application and the "pod also gone" untrack/forget path; this
// loop only ever sets revokedAt earlier than pollLoop otherwise would
// (guarded by the same tracker mutex and the same "only if
// revokedAt==nil" check pollLoop's cleanup block uses, so the two paths
// cannot double-revoke or race destructively). Opt-in via
// --watch-revocation specifically to measure whether watch-based
// reconciliation actually improves revocation latency over polling
// (experiment protocol Task 06/C2: "do not assume watch is faster; measure
// it"), not because it is claimed to be a production improvement by
// itself -- see summary.md for the measured comparison.
func watchRevocationLoop(ctx context.Context, logger *slog.Logger, watchClient client.WithWatch, tracker *podTracker, bpfAgent *loader.Agent) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		w, err := watchClient.Watch(ctx, &aiopsv1alpha1.RuntimeSecurityPolicyList{})
		if err != nil {
			logger.Error("watch RuntimeSecurityPolicy", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}

		for event := range w.ResultChan() {
			if event.Type != watch.Deleted {
				continue
			}
			p, ok := event.Object.(*aiopsv1alpha1.RuntimeSecurityPolicy)
			if !ok {
				continue
			}
			key := types.NamespacedName{Name: p.Name, Namespace: p.Namespace}
			revokeTrackedPolicy(logger, tracker, bpfAgent, key, "watch")
		}
		w.Stop()

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// revokeTrackedPolicy applies the revoke-by-default cgroup update and sets
// revokedAt for a tracked policy key, acquiring tracker.mu itself. Used by
// watchRevocationLoop, which does not otherwise hold the lock.
func revokeTrackedPolicy(logger *slog.Logger, tracker *podTracker, bpfAgent *loader.Agent, key types.NamespacedName, via string) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	revokeTrackedPolicyLocked(logger, tracker, bpfAgent, key, via)
}

// revokeTrackedPolicyLocked is the same operation for callers that already
// hold tracker.mu (reconcileOnce's cleanup loop iterates tracker.tracked
// under the lock and cannot re-acquire it via revokeTrackedPolicy without
// deadlocking). Shared between the poll-based cleanup path and the
// watch-based path (Task 06/C2) so the two mechanisms cannot diverge in
// what "revoked" actually does -- only in how quickly they notice. A no-op
// if the key isn't tracked or was already revoked by whichever path got
// there first.
func revokeTrackedPolicyLocked(logger *slog.Logger, tracker *podTracker, bpfAgent *loader.Agent, key types.NamespacedName, via string) {
	info, tracked := tracker.tracked[key]
	if !tracked || info.revokedAt != nil {
		return
	}
	revokeFailed := false
	for _, cgroupID := range info.cgroupIDs {
		if err := bpfAgent.RevokeCgroup(cgroupID); err != nil {
			logger.Error("revoke cgroup", "policy", key, "cgroupID", cgroupID, "via", via, "error", err)
			revokeFailed = true
		}
	}
	if revokeFailed {
		return
	}
	now := time.Now().UTC()
	info.revokedAt = &now
	tracker.tracked[key] = info
	logger.Info("revoked access", "policy", key, "cgroupIDs", info.cgroupIDs, "via", via)
}

func reconcileOnce(ctx context.Context, logger *slog.Logger, c client.Client, bpfAgent *loader.Agent,
	tracker *podTracker, acc *accumulator, nodeName string, mode lsmdetect.Mode, trust trustConfig) {
	var policies aiopsv1alpha1.RuntimeSecurityPolicyList
	if err := c.List(ctx, &policies); err != nil {
		logger.Error("list RuntimeSecurityPolicy", "error", err)
		return
	}

	// Task 11: loaded fresh each cycle (not cached for the agent's whole
	// lifetime) so a transient trust-anchor-ConfigMap unavailability at
	// startup does not permanently disable validation -- cheap relative
	// to the rest of this cycle's API calls. A nil key (load failed) is
	// passed through deliberately: trustverify.Verify treats a nil key as
	// an immediate, explicit verification failure (VerifyForPod's own
	// "public key is nil" check), so every policy safely falls back to
	// deny-all rather than the agent silently skipping validation.
	var trustAnchorPub ed25519.PublicKey
	if trust.enabled {
		var err error
		trustAnchorPub, err = trustverify.LoadTrustAnchorTOFU(ctx, c, trust.namespace, trust.cmName, trust.cmKey, trust.pinPath)
		if err != nil {
			logger.Error("Task 11/12: load trust anchor public key (all policies will fail worker-side validation this cycle) -- if this is a TOFU pin mismatch, see the error for the exact pinned-vs-observed keys and the re-arm instructions", "error", err)
		}
	}

	seen := map[types.NamespacedName]bool{}
	for i := range policies.Items {
		p := &policies.Items[i]
		key := client.ObjectKeyFromObject(p)

		var pod corev1.Pod
		if err := c.Get(ctx, types.NamespacedName{Name: p.Spec.TargetRef.Name, Namespace: p.Spec.TargetRef.Namespace}, &pod); err != nil {
			continue // target pod not found/not yet scheduled — nothing to do this cycle
		}
		if pod.Spec.NodeName != nodeName || pod.UID == "" {
			continue // not our node
		}
		if p.Spec.Binding.PodUID != "" && string(pod.UID) != p.Spec.Binding.PodUID {
			// The live pod occupying this Name+Namespace is not the pod the
			// signed decision was actually minted for (e.g. the original pod
			// was deleted and a new one recreated with the same name). Treat
			// exactly like "target pod not found": do not track, do not
			// apply, do not mark EnforcementReady. A fresh decision (with
			// the new pod's real UID) must be minted and re-verified before
			// enforcement resumes -- see H100-E04/E09 finding.
			logger.Warn("pod UID mismatch: live pod does not match the decision's signed pod UID, refusing to bind",
				"policy", key, "livePodUID", pod.UID, "decisionPodUID", p.Spec.Binding.PodUID)
			continue
		}

		tracker.mu.Lock()
		_, hadPreviousForDelay := tracker.tracked[key]
		tracker.mu.Unlock()
		if !hadPreviousForDelay {
			// Task 04-A2 test-harness hook: an opt-in, per-pod annotation lets
			// the experiment harness artificially delay this pod's FIRST
			// policy application (and thus t_p) to test whether Δ_PR >= 0
			// still holds when the race is intentionally tightened. Zero
			// effect on any pod without the annotation -- production
			// behavior is unchanged. Only applied once, on first sight of
			// this pod, not on every poll cycle.
			if delayStr, ok := pod.Annotations[injectReadyDelayAnnotation]; ok {
				if delayMs, err := strconv.Atoi(delayStr); err == nil && delayMs > 0 {
					logger.Info("test harness: injecting artificial policy-readiness delay",
						"policy", key, "delayMs", delayMs)
					time.Sleep(time.Duration(delayMs) * time.Millisecond)
				}
			}
		}

		cgroupIDs, err := tracker.resolver.Track(string(pod.UID))
		if err != nil {
			logger.Warn("resolve cgroup for pod", "pod", key, "podUID", pod.UID, "error", err)
			continue
		}

		// Task 11: independently validate this policy against its source
		// AIPlacementDecision before trusting ANY of its content. effectiveP
		// is what actually gets applied below: the received policy p if
		// trusted, or a safe deny-all substitute (same identity/binding,
		// every rule category forced to DefaultAction=deny with empty
		// allow-lists) if not -- "the worker rejects it" means deny, not
		// "skip and leave the cgroup unmonitored."
		effectiveP := p
		if trust.enabled {
			result := trustverify.Verify(ctx, c, trustAnchorPub, trust.ledger, p, string(pod.UID), nodeName, trust.agentImageDigest)
			if !result.Trusted {
				logger.Error("Task 11: worker-side D->P validation FAILED, applying safe deny-all plan instead of received policy",
					"policy", key, "reason", result.Reason)
				denied := p.DeepCopy()
				denied.Spec.Exec = aiopsv1alpha1.ExecPolicy{DefaultAction: "deny"}
				denied.Spec.FileAccess = aiopsv1alpha1.FileAccessPolicy{DefaultAction: "deny"}
				denied.Spec.NetworkEgress = aiopsv1alpha1.NetworkEgressPolicy{DefaultAction: "deny"}
				denied.Spec.DeviceAccess = aiopsv1alpha1.DeviceAccessPolicy{DefaultAction: "deny"}
				effectiveP = denied
			}
		}

		enforcementMode := uint8(0)
		if effectiveP.Spec.EnforcementMode == "enforce" {
			enforcementMode = 1
		}
		// Apply the same policy to every container's leaf cgroup ID in the
		// pod — see cgroupmap's package doc for why a pod can have more than
		// one cgroup ID that bpf_get_current_cgroup_id() might report.
		applyFailed := false
		for _, cgroupID := range cgroupIDs {
			plan, skipped, err := policy.BuildPlan(cgroupID, effectiveP, enforcementMode)
			if err != nil {
				logger.Error("build policy plan", "policy", key, "cgroupID", cgroupID, "error", err)
				applyFailed = true
				break
			}
			for _, s := range skipped {
				logger.Warn("policy rule not enforced/audited (documented limitation)", "policy", key, "field", s.Policy, "cidr", s.CIDR, "reason", s.Reason)
			}
			if err := bpfAgent.ApplyPlan(plan); err != nil {
				logger.Error("apply policy plan", "policy", key, "cgroupID", cgroupID, "error", err)
				applyFailed = true
				break
			}
		}
		if applyFailed {
			continue
		}
		if err := markPolicyEnforcementReady(ctx, c, p, &pod, nodeName, cgroupIDs, mode); err != nil {
			logger.Error("mark policy enforcement ready", "policy", key, "pod", types.NamespacedName{Name: pod.Name, Namespace: pod.Namespace}, "error", err)
			continue
		}

		tracker.mu.Lock()
		prev, hadPrevious := tracker.tracked[key]
		if !hadPrevious || prev.lastAppliedGeneration != p.Generation {
			// Logged once per policy generation (not every poll cycle) so
			// Phase 6's propagation-time measurement can diff this
			// timestamp against the policy's own creation/update time —
			// see experiments/metrics/measure_propagation.sh.
			logger.Info("applied policy", "policy", key, "generation", p.Generation, "cgroupIDs", cgroupIDs)
			// A genuinely new generation just became enforcement-ready for
			// these cgroups: forget any first-observed-event timestamp from
			// a prior generation so the next real eBPF event correctly
			// becomes THIS generation's t_c, not a stale carry-over (mirrors
			// markPolicyEnforcementReady's own FirstObservedOperationMonotonicNs
			// reset on the CRD Status side).
			acc.resetFirstEvent(cgroupIDs)
		}
		next := trackedPod{
			lastAppliedGeneration: p.Generation,
			podUID:                string(pod.UID),
			targetRef:             types.NamespacedName{Name: p.Spec.TargetRef.Name, Namespace: p.Spec.TargetRef.Namespace},
			cgroupIDs:             cgroupIDs,
			decisionID:            p.Spec.Binding.DecisionID,
			decisionHash:          p.Spec.Derivation.DecisionHash,
			policyHash:            p.Spec.Derivation.PolicyHash,
			policyGeneration:      p.Generation,
			lastAuthSync:          time.Now().UTC(),
		}
		if hadPrevious && prev.podUID == next.podUID {
			next.evidenceSequence = prev.evidenceSequence
			next.lastEvidenceDigest = prev.lastEvidenceDigest
			// revokedAt is deliberately NOT carried forward: reaching this
			// line means a policy was just successfully re-applied and
			// EnforcementReady re-confirmed for this pod, i.e. a fresh grant
			// -- the pod's *current* authorization is not revoked, even if
			// an earlier authorization for this same still-running pod was.
			// Carrying the old timestamp forward here was the root cause of
			// every revocation-timing measurement finding "revoked access"
			// only on the first ever revoke-then-reauthorize cycle and
			// never again: the cleanup loop below skips re-revoking (and
			// re-logging) any entry with a non-nil revokedAt, so every
			// subsequent revoke of the same pod was silently treated as
			// "already revoked" without ever actually flipping the cgroup
			// or logging the event. Found and fixed 2026-08-10 (H100-E07).
		}
		tracker.tracked[key] = next
		tracker.mu.Unlock()
		seen[key] = true
	}

	// Revoke any previously tracked policy that has disappeared (deleted, or
	// its target pod is gone) — the "persistence of access after
	// revocation" attack scenario (Phase 5) is exactly this path.
	tracker.mu.Lock()
	for key, info := range tracker.tracked {
		if seen[key] {
			continue
		}

		if info.revokedAt == nil {
			// First cycle where this policy is gone: flip the cgroup(s) to
			// deny-by-default. Deliberately does NOT untrack or clear
			// accumulated counters — see trackedPod.revokedAt's doc comment.
			// Shared with the watch-based path (Task 06/C2) via
			// revokeTrackedPolicyLocked so both mechanisms apply the exact
			// same revocation action; the lock is already held by this
			// loop, so the *Locked variant is required here.
			revokeTrackedPolicyLocked(logger, tracker, bpfAgent, key, "poll")
			continue
		}

		// Already revoked in a prior cycle: only stop tracking once the
		// underlying pod is actually gone too, so evidence keeps reflecting
		// (denied) activity for as long as the pod itself still runs. Must
		// compare by UID, not just Name+Namespace: if the original pod was
		// deleted and a new, different pod was recreated at the same
		// Name+Namespace, that new pod is not the one this tracked entry
		// belongs to and must not keep this entry alive (see H100-E04/E09
		// finding — this mirrors the same live-pod-UID check added above).
		var pod corev1.Pod
		if err := c.Get(ctx, info.targetRef, &pod); err == nil && string(pod.UID) == info.podUID {
			continue // pod still exists (e.g. RuntimeSecurityPolicy deleted independently) — keep reporting
		}
		tracker.resolver.Untrack(info.podUID)
		acc.forgetAll(info.cgroupIDs)
		delete(tracker.tracked, key)
		logger.Info("forgot revoked pod (target pod gone)", "policy", key)
	}
	tracker.mu.Unlock()
}

func markPolicyEnforcementReady(ctx context.Context, c client.Client, p *aiopsv1alpha1.RuntimeSecurityPolicy,
	pod *corev1.Pod, nodeName string, cgroupIDs []uint64, mode lsmdetect.Mode) error {
	now := metav1.Now()
	readyAt := now
	monotonicNs := monotonicRawNs()
	freshGeneration := true
	if p.Status.EnforcementReadyAt != nil &&
		p.Status.AppliedPolicyGeneration == p.Generation {
		if condition := meta.FindStatusCondition(p.Status.Conditions, enforcementReadyConditionType); condition != nil &&
			condition.Status == metav1.ConditionTrue &&
			condition.ObservedGeneration == p.Generation {
			readyAt = *p.Status.EnforcementReadyAt
			freshGeneration = false
			if p.Status.EnforcementReadyMonotonicNs != nil {
				monotonicNs = *p.Status.EnforcementReadyMonotonicNs
			}
		}
	}
	evidenceMode := aiopsv1alpha1.EvidenceModeSimulated
	if mode == lsmdetect.ModeEnforce {
		evidenceMode = aiopsv1alpha1.EvidenceModeReal
	}

	appliedCgroups := make([]string, 0, len(cgroupIDs))
	for _, cgroupID := range cgroupIDs {
		appliedCgroups = append(appliedCgroups, fmt.Sprintf("%d", cgroupID))
	}

	p.Status.EnforcementReadyAt = &readyAt
	p.Status.EnforcementReadyMonotonicNs = &monotonicNs
	if freshGeneration {
		// A new policy generation just became ready: any previously recorded
		// t_c (FirstObservedOperationMonotonicNs) belongs to the PRIOR
		// generation and must not be attributed to this one -- see that
		// field's doc comment. The accumulator's own first-seen tracking for
		// these cgroups is reset by the caller (reconcileOnce) at the same
		// transition.
		p.Status.FirstObservedOperationMonotonicNs = nil
	}
	p.Status.AppliedPolicyGeneration = p.Generation
	p.Status.AppliedNodeName = nodeName
	p.Status.AppliedCgroupIDs = appliedCgroups
	p.Status.EvidenceMode = evidenceMode
	meta.SetStatusCondition(&p.Status.Conditions, metav1.Condition{
		Type:               enforcementReadyConditionType,
		Status:             metav1.ConditionTrue,
		Reason:             enforcementReadyReason,
		Message:            fmt.Sprintf("policy generation %d applied to %d cgroup(s) on node %s", p.Generation, len(cgroupIDs), nodeName),
		ObservedGeneration: p.Generation,
		LastTransitionTime: readyAt,
	})
	if err := c.Status().Update(ctx, p); err != nil {
		return fmt.Errorf("update RuntimeSecurityPolicy enforcement status: %w", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = map[string]string{}
	}
	pod.Annotations[enforcementReadyAnnotation] = readyAt.UTC().Format(time.RFC3339Nano)
	pod.Annotations[enforcementPolicyAnnotation] = fmt.Sprintf("%s/%s", p.Namespace, p.Name)
	if err := c.Update(ctx, pod); err != nil {
		return fmt.Errorf("annotate target pod enforcement readiness: %w", err)
	}
	return nil
}

// firstObservationLoop drains accumulator.firstObserved and writes t_c
// (FirstObservedOperationMonotonicNs) to the owning RuntimeSecurityPolicy's
// Status promptly -- independently of the 30s evidence-emission interval,
// since temporal-closure measurements need sub-second attribution of the
// first externally observed critical operation.
func firstObservationLoop(ctx context.Context, logger *slog.Logger, c client.Client, tracker *podTracker, acc *accumulator) {
	for {
		select {
		case <-ctx.Done():
			return
		case obs := <-acc.firstObserved:
			recordFirstObservedOperation(ctx, logger, c, tracker, obs)
		}
	}
}

func recordFirstObservedOperation(ctx context.Context, logger *slog.Logger, c client.Client, tracker *podTracker, obs firstObservation) {
	tracker.mu.Lock()
	var policyKey types.NamespacedName
	found := false
	for key, info := range tracker.tracked {
		for _, id := range info.cgroupIDs {
			if id == obs.cgroupID {
				policyKey = key
				found = true
			}
		}
	}
	tracker.mu.Unlock()
	if !found {
		// The cgroup produced an event but is not (or not yet, or no longer)
		// bound to a tracked policy -- nothing to attribute t_c to. This is
		// not an error: it is exactly the fail-open startup-window scenario
		// documented in artifacts/audit/implementation-map.md §3 (Task 00),
		// and Task 04-A4's non-cooperative-workload experiment measures it
		// directly rather than papering over it here.
		return
	}

	ns := int64(obs.timestampNs)
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var policy aiopsv1alpha1.RuntimeSecurityPolicy
		if err := c.Get(ctx, policyKey, &policy); err != nil {
			return client.IgnoreNotFound(err)
		}
		if policy.Status.FirstObservedOperationMonotonicNs != nil {
			// Already recorded for the current generation -- t_c is defined
			// as the FIRST observed operation, so a later event must never
			// overwrite it.
			return nil
		}
		policy.Status.FirstObservedOperationMonotonicNs = &ns
		return c.Status().Update(ctx, &policy)
	}); err != nil {
		logger.Error("record first observed operation", "policy", policyKey, "cgroupID", obs.cgroupID, "error", err)
	}
}

func evidenceLoop(ctx context.Context, logger *slog.Logger, c client.Client, tracker *podTracker,
	acc *accumulator, bpfAgent *loader.Agent, signingKey ed25519.PrivateKey, agentImageDigest, nodeName, evidenceNamespace string,
	interval time.Duration, mode lsmdetect.Mode, monitorEpoch, hookDigest string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	evidenceMode := aiopsv1alpha1.EvidenceModeSimulated
	if mode == lsmdetect.ModeEnforce {
		evidenceMode = aiopsv1alpha1.EvidenceModeReal
	}

	// Task 05 B1/B3: dropCountBaseline is the cumulative node-wide
	// event_counters.Dropped value as of the PREVIOUS tick, so each tick's
	// delta (eventsDroppedSinceLastEvidence) reflects loss since the last
	// evidence emission, not since agent start. lastHeartbeat advances every
	// tick regardless of whether any tracked pod had new events, so a
	// verifier can distinguish "workload quiet" from "monitor dead" (a dead
	// monitor cannot itself keep advancing its own heartbeat).
	var dropCountBaseline uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			heartbeat := time.Now().UTC()
			var eventsDroppedSinceLastEvidence int64
			var cumulativeDropCount int64
			if counters, err := bpfAgent.ReadEventCounters(); err != nil {
				// Task 00 discipline applied to this new instrumentation
				// itself: if we cannot even read the loss counters, do not
				// silently assume zero loss -- log it. The evidence for this
				// tick will report a zero delta, which is honestly "unknown,
				// treated as zero" given no better signal is available this
				// cycle, not a claim that zero loss was confirmed.
				logger.Error("read event counters", "error", err)
			} else {
				if counters.Dropped >= dropCountBaseline {
					eventsDroppedSinceLastEvidence = int64(counters.Dropped - dropCountBaseline)
				}
				cumulativeDropCount = int64(counters.Dropped)
				dropCountBaseline = counters.Dropped
			}

			tracker.mu.Lock()
			snapshot := make(map[types.NamespacedName]trackedPod, len(tracker.tracked))
			for k, v := range tracker.tracked {
				snapshot[k] = v
			}
			tracker.mu.Unlock()

			for policyKey, info := range snapshot {
				digest, sequence, ok := emitEvidence(ctx, logger, c, policyKey, info, acc, signingKey, agentImageDigest, nodeName,
					evidenceNamespace, evidenceMode, monitorEpoch, hookDigest, heartbeat, cumulativeDropCount, eventsDroppedSinceLastEvidence)
				if !ok {
					continue
				}
				tracker.mu.Lock()
				if current, exists := tracker.tracked[policyKey]; exists && current.podUID == info.podUID {
					current.lastEvidenceDigest = digest
					current.evidenceSequence = sequence
					tracker.tracked[policyKey] = current
				}
				tracker.mu.Unlock()
			}
		}
	}
}

func emitEvidence(ctx context.Context, logger *slog.Logger, c client.Client, policyKey types.NamespacedName,
	info trackedPod, acc *accumulator, signingKey ed25519.PrivateKey, agentImageDigest, nodeName,
	evidenceNamespace string, evidenceMode aiopsv1alpha1.EvidenceMode, monitorEpoch, hookDigest string,
	heartbeat time.Time, cumulativeDropCount, eventsDroppedSinceLastEvidence int64) (string, int64, bool) {

	counters := acc.snapshotAll(info.cgroupIDs)
	now := time.Now().UTC()
	monitorID := "agent-" + nodeName
	sequence := info.evidenceSequence + 1

	conformance := "conform"
	if counters.ExecDenied > 0 || counters.FileOpenDenied > 0 || counters.ConnectDenied > 0 || counters.DeviceAccessDenied > 0 {
		conformance = "violation"
	}
	if eventsDroppedSinceLastEvidence > 0 {
		// Task 05 B1, Q3: observation is known-incomplete for this emission
		// cycle -- a violation could have gone unobserved just as easily as
		// a conforming operation, so "conform" must never be reported here
		// regardless of what the (incomplete) Behavior counters show. This
		// overrides "violation" too: a violation MAY have been missed
		// entirely, but "incomplete" is the honest state either way since we
		// cannot know whether the true event stream contained more.
		conformance = "incomplete"
	}

	// Task 06/C4: AuthorizationState is deliberately independent of
	// conformance -- a revoked pod can still be "conform" (e.g. idle
	// post-revocation, no denied attempts observed yet) or "violation"
	// (actively attempting denied operations post-revocation). Neither
	// implies the other; a verifier must check both.
	authState := "authorized"
	var revokedAtUnix int64
	if info.revokedAt != nil {
		authState = "revoked"
		revokedAtUnix = info.revokedAt.Unix()
	}

	payload := evidence.Payload{
		PolicyRefName:      policyKey.Name,
		PolicyRefNamespace: policyKey.Namespace,
		TargetRefName:      info.targetRef.Name,
		TargetRefNamespace: info.targetRef.Namespace,
		DecisionID:         info.decisionID,
		DecisionHash:       info.decisionHash,
		PolicyHash:         info.policyHash,
		PolicyGeneration:   info.policyGeneration,
		MonitorID:          monitorID,
		NodeName:           nodeName,
		PodUID:             info.podUID,
		// The status.cgroupID CRD field is a single numeric string
		// (^[0-9]+$), so a multi-container pod's evidence reports only its
		// first container's cgroup ID here — a scoping simplification, not a
		// correctness gap: Behavior counters below are still summed across
		// every container's cgroup ID via acc.snapshotAll.
		CgroupID:            fmt.Sprintf("%d", firstOrZero(info.cgroupIDs)),
		Conformance:         conformance,
		EvidenceMode:        string(evidenceMode),
		AgentImageDigest:    agentImageDigest,
		AgentDigestVerified: true, // this agent is reporting its own digest; the Operator cross-checks it against the DaemonSet spec
		Behavior: evidence.BehaviorCounters{
			ExecAllowed: counters.ExecAllowed, ExecDenied: counters.ExecDenied,
			FileOpenAllowed: counters.FileOpenAllowed, FileOpenDenied: counters.FileOpenDenied,
			ConnectAllowed: counters.ConnectAllowed, ConnectDenied: counters.ConnectDenied,
			DeviceAccessAllowed: counters.DeviceAccessAllowed, DeviceAccessDenied: counters.DeviceAccessDenied,
		},
		EvidenceSequence:               sequence,
		PreviousDigest:                 info.lastEvidenceDigest,
		DropCount:                      cumulativeDropCount,
		EventsDroppedSinceLastEvidence: eventsDroppedSinceLastEvidence,
		MonitorEpoch:                   monitorEpoch,
		LastHeartbeat:                  heartbeat.Unix(),
		HookSetDigest:                  hookDigest,
		RevokedAtUnix:                  revokedAtUnix,
		AuthorizationState:             authState,
		LastAuthorizationSyncUnix:      info.lastAuthSync.Unix(),
		IssuedAt:                       now.Unix(),
		ExpiresAt:                      now.Add(10 * time.Minute).Unix(),
	}

	sig, err := evidence.Sign(signingKey, monitorID, payload)
	if err != nil {
		logger.Error("sign evidence", "policy", policyKey, "error", err)
		return "", 0, false
	}

	obj := &aiopsv1alpha1.RuntimePlacementEvidence{}
	obj.Name = policyKey.Name
	obj.Namespace = evidenceNamespace
	_, err = controllerutil.CreateOrUpdate(ctx, c, obj, func() error {
		obj.Spec.PolicyRef = aiopsv1alpha1.ObjectReference{Name: policyKey.Name, Namespace: policyKey.Namespace}
		obj.Spec.TargetRef = aiopsv1alpha1.ObjectReference{Name: info.targetRef.Name, Namespace: info.targetRef.Namespace}
		obj.Spec.NodeName = nodeName
		return nil
	})
	if err != nil {
		logger.Error("create/update RuntimePlacementEvidence", "policy", policyKey, "error", err)
		return "", 0, false
	}

	obj.Status.DecisionID = payload.DecisionID
	obj.Status.DecisionHash = payload.DecisionHash
	obj.Status.PolicyHash = payload.PolicyHash
	obj.Status.PolicyGeneration = payload.PolicyGeneration
	obj.Status.MonitorID = payload.MonitorID
	obj.Status.PodUID = info.podUID
	obj.Status.CgroupID = payload.CgroupID
	obj.Status.Conformance = conformance
	obj.Status.EvidenceMode = evidenceMode
	obj.Status.AgentIntegrity = aiopsv1alpha1.AgentIntegrityObserved{
		ImageDigest:    agentImageDigest,
		DigestVerified: true,
	}
	obj.Status.Behavior = aiopsv1alpha1.ObservedBehaviorCounters{
		ExecAllowed: counters.ExecAllowed, ExecDenied: counters.ExecDenied,
		FileOpenAllowed: counters.FileOpenAllowed, FileOpenDenied: counters.FileOpenDenied,
		ConnectAllowed: counters.ConnectAllowed, ConnectDenied: counters.ConnectDenied,
		DeviceAccessAllowed: counters.DeviceAccessAllowed, DeviceAccessDenied: counters.DeviceAccessDenied,
	}
	obj.Status.EvidenceSequence = sequence
	obj.Status.PreviousEvidenceDigest = info.lastEvidenceDigest
	obj.Status.DropCount = cumulativeDropCount
	obj.Status.EventsDroppedSinceLastEvidence = eventsDroppedSinceLastEvidence
	obj.Status.MonitorEpoch = monitorEpoch
	obj.Status.LastHeartbeat = metav1.NewTime(heartbeat)
	obj.Status.HookSetDigest = hookDigest
	obj.Status.AuthorizationState = authState
	obj.Status.LastAuthorizationSync = metav1.NewTime(info.lastAuthSync)
	obj.Status.Signature = aiopsv1alpha1.EvidenceSignature{
		Algorithm:     sig.Algorithm,
		KeyIdentifier: sig.KeyIdentifier,
		PayloadDigest: sig.PayloadDigest,
		Signature:     sig.SignatureHex,
		IssuedAt:      metav1.NewTime(sig.IssuedAt),
		ExpiresAt:     metav1.NewTime(sig.ExpiresAt),
	}
	if info.revokedAt != nil {
		// As of Task 06/C4, RevokedAt IS part of the signed payload (see
		// evidence.Payload.RevokedAtUnix) -- the security-relevant fact
		// (access denied post-revocation) was already captured
		// independently by the signed Behavior counters, and this makes
		// the revocation timestamp itself a checkable, signed claim too.
		t := metav1.NewTime(*info.revokedAt)
		obj.Status.RevokedAt = &t
	}
	if err := c.Status().Update(ctx, obj); err != nil {
		logger.Error("update RuntimePlacementEvidence status", "policy", policyKey, "error", err)
		return "", 0, false
	}
	return sig.PayloadDigest, sequence, true
}

// firstObservation is a (cgroup, kernel timestamp) pair pushed onto
// accumulator.firstObserved the moment the FIRST eBPF hook event since the
// last resetFirstEvent is seen for that cgroup -- i.e. a candidate t_c.
type firstObservation struct {
	cgroupID    uint64
	timestampNs uint64
}

// accumulator holds per-cgroup behavior counters, updated from the ring
// buffer reader goroutine and read by the evidence loop. Safe for concurrent use.
type accumulator struct {
	mu          sync.Mutex
	byCID       map[uint64]counters
	firstSeenNs map[uint64]uint64 // cgroupID -> first observed bpf_ktime_get_ns() timestamp since the last resetFirstEvent

	// firstObserved is notified (non-blocking) the first time any event
	// arrives for a cgroup since resetFirstEvent, so a dedicated goroutine
	// can write it to the policy's Status promptly -- t_c needs sub-second
	// attribution, far tighter than the 30s evidence-emission interval this
	// agent otherwise runs on (see artifacts/timing/timestamp-semantics.md).
	firstObserved chan firstObservation
}

type counters struct {
	ExecAllowed, ExecDenied                 int64
	FileOpenAllowed, FileOpenDenied         int64
	ConnectAllowed, ConnectDenied           int64
	DeviceAccessAllowed, DeviceAccessDenied int64
}

func newAccumulator() *accumulator {
	return &accumulator{
		byCID:       make(map[uint64]counters),
		firstSeenNs: make(map[uint64]uint64),
		// Buffered generously relative to expected first-observation
		// frequency (one send per cgroup per resetFirstEvent, not one per
		// event) so a slow consumer cannot make the ring-buffer reader
		// goroutine block; recordFirstObservedOperation drains it promptly.
		firstObserved: make(chan firstObservation, 256),
	}
}

func (a *accumulator) handle(e bpfobjs.AgentEvent) {
	a.mu.Lock()
	_, alreadySeen := a.firstSeenNs[e.CgroupId]
	if !alreadySeen {
		a.firstSeenNs[e.CgroupId] = e.TimestampNs
	}
	c := a.byCID[e.CgroupId]

	allowed := e.Decision == 0 // DECISION_ALLOWED == 0
	switch e.Type {
	case 1: // EVENT_TYPE_EXEC
		if allowed {
			c.ExecAllowed++
		} else {
			c.ExecDenied++
		}
	case 2: // EVENT_TYPE_FILE_OPEN
		if allowed {
			c.FileOpenAllowed++
		} else {
			c.FileOpenDenied++
		}
	case 3: // EVENT_TYPE_CONNECT
		if allowed {
			c.ConnectAllowed++
		} else {
			c.ConnectDenied++
		}
	case 4: // EVENT_TYPE_DEVICE_OPEN
		if allowed {
			c.DeviceAccessAllowed++
		} else {
			c.DeviceAccessDenied++
		}
	}
	a.byCID[e.CgroupId] = c
	a.mu.Unlock()

	if !alreadySeen {
		select {
		case a.firstObserved <- firstObservation{cgroupID: e.CgroupId, timestampNs: e.TimestampNs}:
		default:
			// Buffer full (256 outstanding first-observations never drained):
			// drop rather than block the ring-buffer reader goroutine. This
			// cgroup's t_c will simply not be recorded from this event; it is
			// not silently fabricated from anything else.
		}
	}
}

// resetFirstEvent forgets any previously recorded first-observed timestamp
// for cgroupIDs, so the next event correctly becomes the new policy
// generation's t_c rather than a stale prior generation's. Called by
// reconcileOnce exactly when markPolicyEnforcementReady also resets the CRD
// Status's FirstObservedOperationMonotonicNs -- the two must stay in sync.
func (a *accumulator) resetFirstEvent(cgroupIDs []uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range cgroupIDs {
		delete(a.firstSeenNs, id)
	}
}

// snapshotAll sums counters across every cgroup ID belonging to one pod
// (one per container — see cgroupmap's package doc), since evidence is
// reported per pod, not per container.
func (a *accumulator) snapshotAll(cgroupIDs []uint64) counters {
	a.mu.Lock()
	defer a.mu.Unlock()
	var sum counters
	for _, id := range cgroupIDs {
		c := a.byCID[id]
		sum.ExecAllowed += c.ExecAllowed
		sum.ExecDenied += c.ExecDenied
		sum.FileOpenAllowed += c.FileOpenAllowed
		sum.FileOpenDenied += c.FileOpenDenied
		sum.ConnectAllowed += c.ConnectAllowed
		sum.ConnectDenied += c.ConnectDenied
		sum.DeviceAccessAllowed += c.DeviceAccessAllowed
		sum.DeviceAccessDenied += c.DeviceAccessDenied
	}
	return sum
}

func (a *accumulator) forgetAll(cgroupIDs []uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, id := range cgroupIDs {
		delete(a.byCID, id)
		delete(a.firstSeenNs, id)
	}
}

func firstOrZero(ids []uint64) uint64 {
	if len(ids) == 0 {
		return 0
	}
	return ids[0]
}
