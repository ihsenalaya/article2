#!/usr/bin/env python3
"""TASK-14 expanded campaign, N_pods x event_rate scalability sub-experiment.

Paired pod+policy experiment: unlike task14-scalability-policies.py (CRD-only,
decoupled from real pod scheduling), this creates N_pods *real* pods on the
real worker node and mints one AIPlacementDecision/RuntimeSecurityPolicy per
pod, so EnforcementReady (which requires a real matching pod/cgroup) is
actually exercised.

Definition of "event_rate" used here: this codebase has no built-in
in-container mediated-event generator with a configurable rate (verified by
inspecting operator/cmd/runtime-guard-launcher and the agent) -- the unit of
"event" available to stress is a decision-submission event (AIPlacementDecision
create -> status patch -> policy derivation -> EnforcementReady), not a
syscall/exec stream inside the workload. event_rate therefore controls the
concurrency of decision-submission for a fixed N_pods:
  LOW    = sequential, 1 decision submitted at a time, no artificial delay
  MEDIUM = 5 decisions submitted concurrently
  HIGH   = all N_pods decisions submitted concurrently (full burst)
This is documented here and must be reproduced verbatim in the TASK-14 report
so the metric is not misread as an intra-workload syscall rate.

Usage: python3 task14-scalability-pods.py <kube-context> <node-name> <out-dir>
"""
import csv
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

KUBE_CONTEXT = sys.argv[1]
NODE_NAME = sys.argv[2]
OUT_DIR = Path(sys.argv[3])
REPO_ROOT = Path(__file__).resolve().parents[2]
OPERATOR_DIR = REPO_ROOT / "operator"

TRUST_ANCHOR_ENV = REPO_ROOT / "deploy" / "kind" / "trust-anchor.env"
for line in TRUST_ANCHOR_ENV.read_text().splitlines():
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, _, value = line.partition("=")
    os.environ[key] = value

OUT_DIR.mkdir(parents=True, exist_ok=True)
(OUT_DIR / "raw-data").mkdir(exist_ok=True)

N_PODS_LEVELS = [1, 10, 50, 100]
EVENT_RATES = {"LOW": 1, "MEDIUM": 5, "HIGH": None}  # None = unbounded concurrency

# Unique per script invocation -- see task14-scalability-policies.py for why
# (reused decision-id/nonce across repeated runs gets correctly rejected by
# the controller's anti-replay check, which looks like false saturation).
RUN_TAG = str(int(time.time()))

# Build once -- see task14-scalability-policies.py for why `go run` per call
# is avoided (harness overhead would dominate wall time), and why this is
# built under /tmp rather than OUT_DIR (a relative OUT_DIR would get
# re-resolved against operator/ after the build subprocess's `cd`).
MINT_BIN = Path("/tmp/task14-scalability-pods-mint-test-decision-bin")
subprocess.run(
    f"cd {OPERATOR_DIR} && go build -o {MINT_BIN} ./cmd/mint-test-decision",
    shell=True, check=True,
)


def sh(cmd, check=True, capture=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture, text=True)


def kubectl(args, check=True, capture=True):
    return sh(f"kubectl --context {KUBE_CONTEXT} {args}", check=check, capture=capture)


def sample_resources(namespace, label_selector, container_name):
    out = kubectl(
        f"-n {namespace} get pod -l {label_selector} -o jsonpath='{{.items[0].metadata.name}}'",
        check=False,
    )
    pod_name = out.stdout.strip()
    if not pod_name:
        return {"cpu": None, "memory": None, "pod": None}
    top = kubectl(f"top pod -n {namespace} {pod_name} --no-headers", check=False)
    cpu, mem = None, None
    if top.returncode == 0 and top.stdout.strip():
        parts = top.stdout.split()
        if len(parts) >= 3:
            cpu, mem = parts[1], parts[2]
    return {"cpu": cpu, "memory": mem, "pod": pod_name}


def submit_decision(namespace, n_pods, rate_name, name, pod_uid):
    # Every one of decision-id/nonce's disambiguating components is needed:
    # "scale-pod-0" (name) exists at every N_pods level (1/10/50/100), and
    # each N_pods level runs all three event_rate variants -- so RUN_TAG
    # alone (unique per script invocation) is not enough; n_pods and
    # rate_name must both be included too, or a later combo replays a nonce
    # an earlier combo already used and gets correctly rejected as a replay
    # (observed directly: scale-pod-0 rejected in every single combo after
    # missing the n_pods component -- same bug class fixed twice now).
    mint = sh(
        f"{MINT_BIN} "
        f"--name {name} --namespace {namespace} --target-name {name} "
        f"--pod-uid {pod_uid} --node-identity {NODE_NAME} "
        f"--decision-id scale-pods-{RUN_TAG}-{n_pods}-{rate_name}-{name} --decision-version 1 --decision-epoch 1 "
        f"--decision-nonce nonce-scale-pods-{RUN_TAG}-{n_pods}-{rate_name}-{name}",
        check=False,
    )
    if mint.returncode != 0:
        return False
    apply = sh(f"echo '{mint.stdout}' | kubectl --context {KUBE_CONTEXT} apply -f -", check=False)
    if apply.returncode != 0:
        return False
    patch = kubectl(
        f"-n {namespace} patch aiplacementdecision {name} --subresource=status --type=merge "
        f"-p '{{\"status\":{{\"decision\":\"allow\"}}}}'",
        check=False,
        capture=False,
    )
    return patch.returncode == 0


results = []

for n_pods in N_PODS_LEVELS:
    for rate_name, concurrency in EVENT_RATES.items():
        print(f"=== N_pods={n_pods} event_rate={rate_name} ===", flush=True)
        namespace = f"task14b-scale-pods-{n_pods}-{rate_name.lower()}"
        kubectl(f"delete namespace {namespace} --ignore-not-found", capture=False)
        kubectl(f"create namespace {namespace}", capture=False)

        pod_names = [f"scale-pod-{i}" for i in range(n_pods)]
        pod_yaml = "\n---\n".join(
            f"""apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels: {{ workload: scale-pod }}
spec:
  nodeSelector:
    kubernetes.io/hostname: {NODE_NAME}
  containers:
    - name: main
      image: alpine:3.20
      command: ["sleep", "3600"]"""
            for name in pod_names
        )
        (OUT_DIR / "raw-data" / f"pods_{n_pods}_{rate_name}.yaml").write_text(pod_yaml)
        sh(
            f"kubectl --context {KUBE_CONTEXT} apply -f "
            f"{OUT_DIR / 'raw-data' / f'pods_{n_pods}_{rate_name}.yaml'}",
            check=False,
            capture=False,
        )

        pod_wait_timeout = max(60, n_pods * 3)
        kubectl(
            f"-n {namespace} wait --for=condition=Ready pod -l workload=scale-pod "
            f"--timeout={pod_wait_timeout}s",
            check=False,
            capture=False,
        )
        uid_out = kubectl(
            f"-n {namespace} get pod -l workload=scale-pod "
            "-o jsonpath='{range .items[*]}{.metadata.name}{\" \"}{.metadata.uid}{\"\\n\"}{end}'",
            check=False,
        )
        uid_map = {}
        for line in uid_out.stdout.splitlines():
            parts = line.split()
            if len(parts) == 2:
                uid_map[parts[0]] = parts[1]
        pods_ready = len(uid_map)

        t_start = time.monotonic()
        failures = 0
        if concurrency is None:
            workers = max(1, len(uid_map))
        else:
            workers = concurrency
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            futs = [
                pool.submit(submit_decision, namespace, n_pods, rate_name, name, uid)
                for name, uid in uid_map.items()
            ]
            for f in futs:
                if not f.result():
                    failures += 1
        t_submit_done = time.monotonic()

        timeout_s = max(60, n_pods * 3)
        active_ready_count = 0
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            out = kubectl(
                f"-n {namespace} get runtimesecuritypolicy -o jsonpath="
                "'{range .items[*]}{.status.decision}{\" \"}"
                "{.status.conditions[?(@.type==\"EnforcementReady\")].status}{\"\\n\"}{end}'",
                check=False,
            )
            active_ready_count = sum(
                1
                for line in out.stdout.splitlines()
                if line.strip().split() == ["active", "True"]
            )
            if active_ready_count >= pods_ready - failures:
                break
            time.sleep(1)
        t_ready_done = time.monotonic()

        controller_res = sample_resources(
            "runtime-guard-operator-system", "control-plane=controller-manager", "manager"
        )
        agent_res = sample_resources("runtime-guard-agent-system", "app=runtime-guard-agent", "agent")

        row = {
            "n_pods": n_pods,
            "event_rate": rate_name,
            "pods_requested": n_pods,
            "pods_ready": pods_ready,
            "submission_wall_seconds": round(t_submit_done - t_start, 2),
            "enforcement_ready_wall_seconds": round(t_ready_done - t_submit_done, 2),
            "total_wall_seconds": round(t_ready_done - t_start, 2),
            "submission_failures": failures,
            "active_and_ready_count": active_ready_count,
            "expected_count": pods_ready,
            "saturated": active_ready_count < pods_ready,
            "controller_cpu": controller_res["cpu"],
            "controller_memory": controller_res["memory"],
            "agent_cpu": agent_res["cpu"],
            "agent_memory": agent_res["memory"],
        }
        results.append(row)
        print(json.dumps(row), flush=True)

        (OUT_DIR / "raw-data" / f"n_pods_{n_pods}_{rate_name}_status.txt").write_text(
            kubectl(f"-n {namespace} get runtimesecuritypolicy -o wide", check=False).stdout
        )

        if row["saturated"]:
            print(
                f"SATURATION POINT reached at N_pods={n_pods} event_rate={rate_name}: "
                f"only {active_ready_count}/{pods_ready} reached active+EnforcementReady "
                f"within {timeout_s}s",
                flush=True,
            )

        kubectl(f"delete namespace {namespace} --ignore-not-found", capture=False)

csv_path = OUT_DIR / "raw-data" / "scalability-pods-results.csv"
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
    writer.writeheader()
    writer.writerows(results)
print(f"results written to {csv_path}")
