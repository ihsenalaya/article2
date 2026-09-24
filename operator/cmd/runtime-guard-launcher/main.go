package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
)

const enforcementReadyConditionType = "EnforcementReady"

// monotonicRawNs reads CLOCK_MONOTONIC_RAW, the node-local userspace clock
// this campaign uses for t_r (see artifacts/timing/timestamp-semantics.md).
// Only meaningful compared against another CLOCK_MONOTONIC_RAW reading
// captured on the SAME node -- the agent's EnforcementReadyMonotonicNs is,
// because the launcher runs in the same pod on the same node as the agent
// that applied this policy.
func monotonicRawNs() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &ts); err != nil {
		return 0
	}
	return unix.TimespecToNsec(ts)
}

type releaseRecord struct {
	GateStartedAt           string   `json:"gate_started_at"`
	PolicyNamespace         string   `json:"policy_namespace"`
	PolicyName              string   `json:"policy_name"`
	PolicyCreationTimestamp string   `json:"policy_creation_timestamp,omitempty"`
	PolicyGeneration        int64    `json:"policy_generation"`
	AppliedPolicyGeneration int64    `json:"applied_policy_generation"`
	AppliedNodeName         string   `json:"applied_node_name,omitempty"`
	AppliedCgroupIDs        []string `json:"applied_cgroup_ids,omitempty"`
	EvidenceMode            string   `json:"evidence_mode,omitempty"`
	EnforcementReadyAt      string   `json:"enforcement_ready_at"`
	// EnforcementReadyMonotonicNs is t_p, read directly from the agent's own
	// CLOCK_MONOTONIC_RAW reading (RuntimeSecurityPolicy.Status) rather than
	// this wall-clock string -- see EnforcementReadyMonotonicNs's doc
	// comment on the CRD type. Nil if the agent build deployed predates this
	// field (older RuntimeSecurityPolicy Status).
	EnforcementReadyMonotonicNs *int64 `json:"enforcement_ready_monotonic_ns,omitempty"`
	GateReleasedAt              string `json:"gate_released_at"`
	// GateReleasedMonotonicNs is t_r: this process's own CLOCK_MONOTONIC_RAW
	// reading at the instant it observed EnforcementReady and decided to
	// release, directly comparable to EnforcementReadyMonotonicNs (same
	// node, same clock).
	GateReleasedMonotonicNs int64 `json:"gate_released_monotonic_ns"`
	// t_c (the first externally observed critical operation) is
	// deliberately NOT reported here: this launcher process never performs
	// the workload's critical operation itself (a separate container in the
	// same pod does, after this launcher's ready-file appears), so it has
	// no legitimate way to observe it. Read
	// RuntimeSecurityPolicy.Status.FirstObservedOperationMonotonicNs
	// instead -- populated exclusively from real eBPF observations (see
	// artifacts/timing/timestamp-semantics.md). A prior version of this
	// launcher self-reported "critical_operation_at" as a copy of its own
	// release timestamp, which made Δ_RC vacuously zero; that field is
	// removed, not merely deprecated, so nothing can accidentally read it.
}

func main() {
	var (
		policyName      = flag.String("policy-name", os.Getenv("RUNTIME_GUARD_POLICY_NAME"), "RuntimeSecurityPolicy name to wait for")
		policyNamespace = flag.String("policy-namespace", envOrDefault("RUNTIME_GUARD_POLICY_NAMESPACE", os.Getenv("POD_NAMESPACE")), "RuntimeSecurityPolicy namespace")
		timeout         = flag.Duration("timeout", 2*time.Minute, "maximum time to wait for EnforcementReady")
		pollInterval    = flag.Duration("poll-interval", 500*time.Millisecond, "poll interval for policy readiness")
		hold            = flag.Duration("hold", 30*time.Second, "how long to keep the container alive after releasing the workload")
		readyFile       = flag.String("ready-file", "/tmp/runtime-guard-ready", "file written after EnforcementReady and checked by --probe-ready")
		probeReady      = flag.Bool("probe-ready", false, "exit 0 only when ready-file exists")
	)
	flag.Parse()

	if *probeReady {
		os.Exit(probeReadyFile(*readyFile))
	}

	if *policyName == "" || *policyNamespace == "" {
		fmt.Fprintln(os.Stderr, "policy-name and policy-namespace are required")
		os.Exit(2)
	}

	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		fmt.Fprintln(os.Stderr, "register scheme:", err)
		os.Exit(2)
	}
	kubeConfig, err := config.GetConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "load in-cluster config:", err)
		os.Exit(2)
	}
	kubeClient, err := client.New(kubeConfig, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, "create client:", err)
		os.Exit(2)
	}

	startedAt := time.Now().UTC()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	ticker := time.NewTicker(*pollInterval)
	defer ticker.Stop()
	key := types.NamespacedName{Name: *policyName, Namespace: *policyNamespace}

	for {
		var policy aiopsv1alpha1.RuntimeSecurityPolicy
		if err := kubeClient.Get(ctx, key, &policy); err == nil && isCurrentEnforcementReady(&policy) {
			// Captured as early as possible after the Get that confirmed
			// readiness, before any file/stdout I/O below, so this reading
			// is as close as practical to "the instant this process learned
			// it may proceed" -- see t_r's definition in
			// artifacts/timing/timestamp-semantics.md.
			releasedAtMonotonicNs := monotonicRawNs()
			releasedAt := time.Now().UTC()
			record := releaseRecord{
				GateStartedAt:               startedAt.Format(time.RFC3339Nano),
				PolicyNamespace:             policy.Namespace,
				PolicyName:                  policy.Name,
				PolicyCreationTimestamp:     policy.CreationTimestamp.UTC().Format(time.RFC3339Nano),
				PolicyGeneration:            policy.Generation,
				AppliedPolicyGeneration:     policy.Status.AppliedPolicyGeneration,
				AppliedNodeName:             policy.Status.AppliedNodeName,
				AppliedCgroupIDs:            policy.Status.AppliedCgroupIDs,
				EvidenceMode:                string(policy.Status.EvidenceMode),
				EnforcementReadyAt:          policy.Status.EnforcementReadyAt.UTC().Format(time.RFC3339Nano),
				EnforcementReadyMonotonicNs: policy.Status.EnforcementReadyMonotonicNs,
				GateReleasedAt:              releasedAt.Format(time.RFC3339Nano),
				GateReleasedMonotonicNs:     releasedAtMonotonicNs,
			}
			if err := os.WriteFile(*readyFile, []byte(releasedAt.Format(time.RFC3339Nano)+"\n"), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "write ready file:", err)
				os.Exit(2)
			}
			if err := json.NewEncoder(os.Stdout).Encode(record); err != nil {
				fmt.Fprintln(os.Stderr, "encode release record:", err)
				os.Exit(2)
			}
			time.Sleep(*hold)
			return
		}

		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "timed out waiting for current EnforcementReady on %s/%s\n", key.Namespace, key.Name)
			os.Exit(1)
		case <-ticker.C:
		}
	}
}

func isCurrentEnforcementReady(policy *aiopsv1alpha1.RuntimeSecurityPolicy) bool {
	if policy.Status.EnforcementReadyAt == nil {
		return false
	}
	if policy.Status.AppliedPolicyGeneration != policy.Generation {
		return false
	}
	condition := meta.FindStatusCondition(policy.Status.Conditions, enforcementReadyConditionType)
	return condition != nil && condition.Status == metav1.ConditionTrue && condition.ObservedGeneration == policy.Generation
}

func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func probeReadyFile(path string) int {
	if _, err := os.Stat(path); err != nil {
		return 1
	}
	return 0
}
