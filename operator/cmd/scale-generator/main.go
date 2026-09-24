// Command scale-generator is Task 08's IN-CLUSTER load generator (master
// prompt section 10): "Discard WSL2 -> sequential kubectl as a scalability
// measurement path... Create an IN-CLUSTER load generator. Prefer a
// program using client-go rather than spawning kubectl repeatedly." This
// runs as a pod inside the cluster, using an in-cluster client-go client
// (no kubectl subprocesses, no cross-network WSL2 latency), mints real
// Ed25519-signed AIPlacementDecision objects directly via
// pkg/token+pkg/crypto (the same signing logic mint-test-decision uses,
// reused in-process rather than shelled out to per-decision), creates a
// real lightweight pod per decision, and tracks convergence via a single
// periodic List() call scanning all tracked names each tick (not N
// individual per-object polls, which would not scale cleanly to N=100+
// submissions against a 2-vCPU control plane). An earlier version used a
// raw client-go/controller-runtime Watch() instead; that was dropped in
// favor of this simpler design during debugging of what turned out to be
// an unrelated bug (see run-*.sh / lib.sh's imagePullPolicy: Always note --
// the Job spec omitted imagePullPolicy, so the node kept reusing the
// first-ever cached image build across every subsequent code change and
// rebuild, made worse by reusing the same image tag every time; every
// apparent "fix" during that investigation was never actually deployed
// until that was found). The watch-based version was not conclusively
// shown to be broken; polling was kept anyway since it is simpler, has an
// unambiguous cost model, and matches the pattern every other experiment
// in this campaign already relies on.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"

	aiopsv1alpha1 "github.com/ihsenalaya/runtime-guard-operator/api/v1alpha1"
	"github.com/ihsenalaya/runtime-guard-operator/internal/upstream"
	platformcrypto "github.com/ihsenalaya/runtime-guard-operator/pkg/crypto"
	placementtoken "github.com/ihsenalaya/runtime-guard-operator/pkg/token"
)

type record struct {
	Index                        int     `json:"index"`
	Name                         string  `json:"name"`
	TSubmitUnix                  float64 `json:"t_submit_unix"`
	TPodScheduledUnix            float64 `json:"t_pod_scheduled_unix,omitempty"`
	TDecisionAppliedUnix         float64 `json:"t_decision_applied_unix,omitempty"`
	TPolicyCreatedUnix           float64 `json:"t_policy_created_unix,omitempty"`
	TEnforcementReadyUnix        float64 `json:"t_enforcement_ready_unix,omitempty"`
	SubmitToAcceptedSeconds      float64 `json:"submit_to_accepted_seconds,omitempty"`
	SubmitToPolicyCreatedSeconds float64 `json:"submit_to_policy_created_seconds,omitempty"`
	SubmitToReadySeconds         float64 `json:"submit_to_ready_seconds,omitempty"`
	Outcome                      string  `json:"outcome"`
}

type metricsSample struct {
	TimeUnix         float64 `json:"time_unix"`
	OperatorCPUMilli int64   `json:"operator_cpu_milli"`
	OperatorMemBytes int64   `json:"operator_mem_bytes"`
	AgentCPUMilli    int64   `json:"agent_cpu_milli"`
	AgentMemBytes    int64   `json:"agent_mem_bytes"`
}

func main() {
	var (
		n                 = flag.Int("n", 10, "total number of decisions/pods to submit")
		concurrency       = flag.Int("concurrency", 10, "max concurrent in-flight submissions")
		namespace         = flag.String("namespace", "workloads", "namespace for pods/decisions")
		nodeName          = flag.String("node-name", "", "target node identity (required, must match a real schedulable node)")
		privKeyHex        = flag.String("priv-key-hex", os.Getenv("TRUST_ANCHOR_PRIVATE_KEY_HEX"), "hex-encoded Ed25519 trust-anchor private key")
		runID             = flag.String("run-id", "", "unique label value for this run's pods/decisions (required)")
		convergeTimeout   = flag.Duration("converge-timeout", 5*time.Minute, "max time to wait for all N to reach EnforcementReady")
		metricsInterval   = flag.Duration("metrics-interval", 2*time.Second, "sampling interval for controller/agent CPU+memory via metrics.k8s.io")
		operatorNamespace = flag.String("operator-namespace", "runtime-guard-operator-system", "")
		agentNamespace    = flag.String("agent-namespace", "runtime-guard-agent-system", "")
		image             = flag.String("image", "busybox:1.36", "workload pod image")
	)
	flag.Parse()

	if *nodeName == "" || *runID == "" || *privKeyHex == "" {
		log.Fatal("node-name, run-id, and priv-key-hex are all required")
	}

	priv, err := platformcrypto.PrivKeyFromHex(*privKeyHex)
	if err != nil {
		log.Fatalf("invalid private key: %v", err)
	}

	scheme := runtime.NewScheme()
	if err := aiopsv1alpha1.AddToScheme(scheme); err != nil {
		log.Fatalf("register scheme: %v", err)
	}
	if err := corev1.AddToScheme(scheme); err != nil {
		log.Fatalf("register scheme: %v", err)
	}
	if err := upstream.AddToScheme(scheme); err != nil {
		log.Fatalf("register scheme: %v", err)
	}

	restConfig, err := config.GetConfig()
	if err != nil {
		log.Fatalf("get in-cluster config: %v", err)
	}
	// client-go's default QPS=5/Burst=10 is far below the concurrency this
	// generator drives (up to 100+ concurrent submissions/polls); left at
	// the default, client-side throttling fires and client-go logs a
	// "Waited for Xs due to client-side throttling" line via klog. Since
	// container runtimes interleave stdout+stderr into one stream, kubectl
	// logs can place that line ahead of this program's single JSON result
	// line. Raising the limits removes the throttling (a real scalability
	// concern in its own right, distinct from the log-mixing).
	restConfig.QPS = 200
	restConfig.Burst = 400
	c, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("create client: %v", err)
	}
	metricsClient, err := newMetricsClient(restConfig)
	if err != nil {
		log.Fatalf("create metrics client: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *convergeTimeout+30*time.Second)
	defer cancel()

	records := make([]*record, *n)
	var mu sync.Mutex
	nameToIndex := make(map[string]int, *n)
	for i := 0; i < *n; i++ {
		name := fmt.Sprintf("scale-%s-%d", *runID, i)
		records[i] = &record{Index: i, Name: name, Outcome: "in_progress"}
		nameToIndex[name] = i
	}

	// Metrics sampling goroutine: independent of submission progress,
	// samples controller/agent CPU+memory on a fixed tick for the whole
	// run so resource usage during convergence, not just at the end, is
	// captured.
	var metricsSamples []metricsSample
	var metricsMu sync.Mutex
	metricsDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(*metricsInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				close(metricsDone)
				return
			case <-metricsDone:
				return
			case <-ticker.C:
				s := sampleMetrics(ctx, metricsClient, *operatorNamespace, *agentNamespace)
				metricsMu.Lock()
				metricsSamples = append(metricsSamples, s)
				metricsMu.Unlock()
			}
		}
	}()

	// Convergence-tracking goroutine: a single List() of pods and a single
	// List() of RuntimeSecurityPolicy per tick, scanning all N tracked
	// names against each list. See the package doc comment for why this
	// replaced an earlier Watch()-based version.
	pollerDone := make(chan struct{})
	go func() {
		defer close(pollerDone)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := float64(time.Now().UnixNano()) / 1e9

				var pods corev1.PodList
				if err := c.List(ctx, &pods, client.InNamespace(*namespace)); err == nil {
					mu.Lock()
					for _, pod := range pods.Items {
						idx, found := nameToIndex[pod.Name]
						if !found || records[idx].TPodScheduledUnix != 0 {
							continue
						}
						if pod.Spec.NodeName != "" {
							records[idx].TPodScheduledUnix = now
						}
					}
					mu.Unlock()
				}

				var policies aiopsv1alpha1.RuntimeSecurityPolicyList
				if err := c.List(ctx, &policies, client.InNamespace(*namespace)); err == nil {
					mu.Lock()
					for _, p := range policies.Items {
						idx, found := nameToIndex[p.Name]
						if !found {
							continue
						}
						if records[idx].TPolicyCreatedUnix == 0 {
							records[idx].TPolicyCreatedUnix = now
						}
						if p.Status.EnforcementReadyAt != nil && p.Status.Decision == "active" && records[idx].TEnforcementReadyUnix == 0 {
							records[idx].TEnforcementReadyUnix = now
						}
					}
					mu.Unlock()
				}
			}
		}
	}()

	// Submission: bounded-concurrency worker pool, in-process signing (no
	// per-decision subprocess spawn -- the protocol's own rationale
	// for preferring client-go over shelling out to kubectl repeatedly
	// applies equally to shelling out to a mint-test-decision subprocess
	// per item).
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup
	for i := 0; i < *n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			submitOne(ctx, c, priv, *namespace, *nodeName, *runID, *image, records[i], &mu)
		}(i)
	}
	wg.Wait()

	// Wait for all submitted (non-failed) items to reach EnforcementReady,
	// bounded by convergeTimeout.
	deadline := time.Now().Add(*convergeTimeout)
	for time.Now().Before(deadline) {
		mu.Lock()
		allDone := true
		for _, r := range records {
			if r.Outcome == "submitted" && r.TEnforcementReadyUnix == 0 {
				allDone = false
				break
			}
		}
		mu.Unlock()
		if allDone {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	cancel()
	<-pollerDone
	<-metricsDone

	mu.Lock()
	for _, r := range records {
		if r.Outcome != "submitted" {
			continue
		}
		if r.TDecisionAppliedUnix > 0 {
			r.SubmitToAcceptedSeconds = r.TDecisionAppliedUnix - r.TSubmitUnix
		}
		if r.TPolicyCreatedUnix > 0 {
			r.SubmitToPolicyCreatedSeconds = r.TPolicyCreatedUnix - r.TSubmitUnix
		}
		if r.TEnforcementReadyUnix > 0 {
			r.SubmitToReadySeconds = r.TEnforcementReadyUnix - r.TSubmitUnix
			r.Outcome = "converged"
		} else {
			r.Outcome = "timed_out"
		}
	}
	mu.Unlock()

	out := struct {
		RunID          string          `json:"run_id"`
		N              int             `json:"n"`
		Concurrency    int             `json:"concurrency"`
		Records        []*record       `json:"records"`
		MetricsSamples []metricsSample `json:"metrics_samples"`
	}{RunID: *runID, N: *n, Concurrency: *concurrency, Records: records, MetricsSamples: metricsSamples}

	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		log.Fatalf("encode output: %v", err)
	}
}

func submitOne(ctx context.Context, c client.Client, priv []byte, namespace, nodeName, runID, image string, rec *record, mu *sync.Mutex) {
	mu.Lock()
	rec.TSubmitUnix = float64(time.Now().UnixNano()) / 1e9
	mu.Unlock()

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rec.Name,
			Namespace: namespace,
			Labels:    map[string]string{"scale-run": runID, "experiment": "scale"},
		},
		Spec: corev1.PodSpec{
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{Name: "workload", Image: image, Command: []string{"sleep", "3600"}},
			},
		},
	}
	if err := c.Create(ctx, pod); err != nil {
		markFailed(mu, rec, "pod_create_failed: "+err.Error())
		return
	}

	// Wait for the pod to be scheduled (has a node + UID) -- needed before
	// the decision can be minted, since it must be bound to the real UID.
	var uid string
	for i := 0; i < 120; i++ {
		var live corev1.Pod
		if err := c.Get(ctx, client.ObjectKeyFromObject(pod), &live); err == nil && live.Spec.NodeName != "" && live.UID != "" {
			uid = string(live.UID)
			break
		}
		select {
		case <-ctx.Done():
			markFailed(mu, rec, "context done waiting for pod scheduling")
			return
		case <-time.After(250 * time.Millisecond):
		}
	}
	if uid == "" {
		markFailed(mu, rec, "pod never scheduled")
		return
	}

	now := time.Now().UTC()
	payload := placementtoken.Payload{
		DecisionID:      fmt.Sprintf("%s/%s", namespace, rec.Name),
		DecisionVersion: 1,
		DecisionEpoch:   1,
		DecisionNonce:   fmt.Sprintf("%d", time.Now().UnixNano()),
		PodUID:          uid,
		PodSpecHash:     "scale-test-pod-spec-hash",
		ImageDigest:     "scale-test-image-digest",
		ModelDigest:     "scale-test-model-digest",
		NodeIdentity:    nodeName,
		RuntimeClass:    "kata-qemu-snp",
		EvidenceHash:    "scale-test-evidence-hash",
		PolicyHash:      "scale-test-policy-hash",
		IssuedAt:        now.Unix(),
		ExpiresAt:       now.Add(30 * time.Minute).Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		markFailed(mu, rec, "marshal payload: "+err.Error())
		return
	}
	tok := placementtoken.Token{Payload: payload, Signature: platformcrypto.Ed25519Sign(priv, data)}
	tokJSON, err := json.Marshal(tok)
	if err != nil {
		markFailed(mu, rec, "marshal token: "+err.Error())
		return
	}

	decision := &upstream.AIPlacementDecision{
		ObjectMeta: metav1.ObjectMeta{
			Name:      rec.Name,
			Namespace: namespace,
			Labels:    map[string]string{"scale-run": runID, "experiment": "scale"},
			Annotations: map[string]string{
				"ai.sovereign.io/placement-token": string(tokJSON),
			},
		},
		Spec: upstream.AIPlacementDecisionSpec{
			TargetRef:     upstream.ObjectRef{Name: rec.Name, Namespace: namespace},
			PolicyRef:     upstream.ObjectRef{Name: "test-policy", Namespace: namespace},
			SchedulerName: "ai-attestation-scheduler",
		},
	}
	if err := c.Create(ctx, decision); err != nil {
		markFailed(mu, rec, "decision_create_failed: "+err.Error())
		return
	}
	decision.Status.Decision = "allow"
	if err := c.Status().Update(ctx, decision); err != nil {
		markFailed(mu, rec, "decision_status_update_failed: "+err.Error())
		return
	}

	mu.Lock()
	rec.TDecisionAppliedUnix = float64(time.Now().UnixNano()) / 1e9
	rec.Outcome = "submitted"
	mu.Unlock()
}

func markFailed(mu *sync.Mutex, rec *record, reason string) {
	mu.Lock()
	rec.Outcome = "failed: " + reason
	mu.Unlock()
}

func newMetricsClient(cfg *rest.Config) (client.Client, error) {
	scheme := runtime.NewScheme()
	if err := metricsv1beta1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	return client.New(cfg, client.Options{Scheme: scheme})
}

func sampleMetrics(ctx context.Context, mc client.Client, operatorNS, agentNS string) metricsSample {
	s := metricsSample{TimeUnix: float64(time.Now().UnixNano()) / 1e9}
	var opList metricsv1beta1.PodMetricsList
	if err := mc.List(ctx, &opList, client.InNamespace(operatorNS)); err == nil {
		for _, pm := range opList.Items {
			for _, ct := range pm.Containers {
				s.OperatorCPUMilli += ct.Usage.Cpu().MilliValue()
				s.OperatorMemBytes += ct.Usage.Memory().Value()
			}
		}
	}
	var agList metricsv1beta1.PodMetricsList
	if err := mc.List(ctx, &agList, client.InNamespace(agentNS)); err == nil {
		for _, pm := range agList.Items {
			for _, ct := range pm.Containers {
				s.AgentCPUMilli += ct.Usage.Cpu().MilliValue()
				s.AgentMemBytes += ct.Usage.Memory().Value()
			}
		}
	}
	return s
}
