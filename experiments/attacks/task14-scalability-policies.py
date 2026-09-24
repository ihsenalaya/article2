#!/usr/bin/env python3
"""TASK-14 expanded campaign, N_policies scalability sub-experiment.

Decoupled from N_pods scaling deliberately: RuntimeSecurityPolicy/
AIPlacementDecision CRD reconciliation (controller-side verify-then-derive
pipeline) can be stressed at N_policies=500 without needing 500 real running
pods (EnforcementReady requires a real matching pod/cgroup on the node and
is NOT what this sub-experiment measures -- see task14-scalability-pods.py
for the paired pod+policy experiment that does exercise EnforcementReady).
This isolates controller CRD-reconciliation throughput/CPU/memory as its own
scalability dimension, which is the honest way to test N_policies=500 on a
2-node, 2-vCPU-per-node cluster without conflating it with pod scheduling
capacity.

Usage: python3 task14-scalability-policies.py <kube-context> <node-identity> <out-dir>
"""
import csv
import json
import os
import subprocess
import sys
import time
from pathlib import Path

KUBE_CONTEXT = sys.argv[1]
NODE_IDENTITY = sys.argv[2]
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

N_POLICIES_LEVELS = [1, 10, 100, 500]

# Unique per script invocation: decision-id/nonce must not repeat across runs
# of this script, or the controller's (correctly-functioning) anti-replay
# check rejects the reused nonce and every decision comes back
# decision=rejected -- observed directly against this cluster while
# iterating on this script (repeated debug runs reused the same static
# "scale-decision-{n}-{i}" / "nonce-scale-{n}-{i}" values and got rejected,
# which looked like a false "saturation point" until the RuntimeSecurityPolicy
# status was checked directly and showed decision=rejected, not a timeout).
RUN_TAG = str(int(time.time()))

# Build mint-test-decision once instead of `go run`-ing it per iteration: `go
# run` re-resolves/re-links on every invocation, which dominates wall time at
# N=500 and would misattribute test-harness overhead to controller
# scalability. The compiled binary removes that overhead so the measured
# create_wall_seconds reflects mint+apply+patch cost, not go toolchain cost.
# Built under /tmp, not OUT_DIR: OUT_DIR is a relative Path (from argv), and
# the build subprocess does `cd {OPERATOR_DIR} && go build -o {OUT_DIR}/...`
# -- a relative OUT_DIR gets re-resolved against operator/ after that cd,
# silently landing the binary at operator/<OUT_DIR>/... instead of the
# intended path relative to the repo root. An initial (wrong) hypothesis
# blamed this on WSL2/drvfs; the actual cause, confirmed by finding the
# stray binary at operator/<OUT_DIR>/.../mint-test-decision-bin, is
# this relative-path-plus-cd interaction. /tmp is absolute, so it isn't
# affected either way.
MINT_BIN = Path("/tmp/task14-scalability-mint-test-decision-bin")
subprocess.run(
    f"cd {OPERATOR_DIR} && go build -o {MINT_BIN} ./cmd/mint-test-decision",
    shell=True, check=True,
)


def sh(cmd, check=True, capture=True):
    return subprocess.run(cmd, shell=True, check=check, capture_output=capture, text=True)


def kubectl(args, check=True, capture=True):
    return sh(f"kubectl --context {KUBE_CONTEXT} {args}", check=check, capture=capture)


def sample_controller_resources():
    """Read the controller pod's cgroup CPU/memory directly via kubectl exec
    into the node (no metrics-server dependency, no assumption it's
    installed)."""
    out = kubectl(
        "-n runtime-guard-operator-system get pod -l control-plane=controller-manager "
        "-o jsonpath='{.items[0].metadata.name}'",
        check=False,
    )
    pod_name = out.stdout.strip()
    if not pod_name:
        return {"cpu": None, "memory": None, "pod": None}
    top = kubectl(f"top pod -n runtime-guard-operator-system {pod_name} --no-headers", check=False)
    cpu, mem = None, None
    if top.returncode == 0 and top.stdout.strip():
        parts = top.stdout.split()
        if len(parts) >= 3:
            cpu, mem = parts[1], parts[2]
    return {"cpu": cpu, "memory": mem, "pod": pod_name}


results = []

for n_policies in N_POLICIES_LEVELS:
    print(f"=== N_policies={n_policies} ===", flush=True)
    namespace = f"task14b-scale-policies-{n_policies}"
    kubectl(f"delete namespace {namespace} --ignore-not-found", capture=False)
    kubectl(f"create namespace {namespace}", capture=False)

    t_start = time.monotonic()
    failures = 0
    for i in range(n_policies):
        name = f"scale-policy-{i}"
        mint = sh(
            f"{MINT_BIN} "
            f"--name {name} --namespace {namespace} --target-name {name} "
            f"--pod-uid pod-{name} --node-identity {NODE_IDENTITY} "
            f"--decision-id scale-decision-{RUN_TAG}-{n_policies}-{i} --decision-version 1 --decision-epoch 1 "
            f"--decision-nonce nonce-scale-{RUN_TAG}-{n_policies}-{i}",
            check=False,
        )
        if mint.returncode != 0:
            failures += 1
            continue
        apply = sh(f"echo '{mint.stdout}' | kubectl --context {KUBE_CONTEXT} apply -f -", check=False)
        if apply.returncode != 0:
            failures += 1
            continue
        kubectl(
            f"-n {namespace} patch aiplacementdecision {name} --subresource=status --type=merge "
            f"-p '{{\"status\":{{\"decision\":\"allow\"}}}}'",
            check=False,
            capture=False,
        )
    t_create_done = time.monotonic()

    # Poll until all N_policies RuntimeSecurityPolicy objects report decision=active
    # (verification pipeline complete), or timeout.
    timeout_s = max(60, n_policies * 2)
    active_count = 0
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        out = kubectl(
            f"-n {namespace} get runtimesecuritypolicy -o jsonpath='{{range .items[*]}}{{.status.decision}}{{\"\\n\"}}{{end}}'",
            check=False,
        )
        lines = [l for l in out.stdout.splitlines() if l.strip()]
        active_count = sum(1 for l in lines if l.strip() == "active")
        if active_count >= n_policies - failures:
            break
        time.sleep(1)
    t_active_done = time.monotonic()

    resources = sample_controller_resources()

    row = {
        "n_policies": n_policies,
        "create_wall_seconds": round(t_create_done - t_start, 2),
        "reconcile_wall_seconds": round(t_active_done - t_create_done, 2),
        "total_wall_seconds": round(t_active_done - t_start, 2),
        "mint_or_apply_failures": failures,
        "active_count": active_count,
        "expected_count": n_policies,
        "saturated": active_count < n_policies,
        "controller_cpu": resources["cpu"],
        "controller_memory": resources["memory"],
        "controller_pod": resources["pod"],
    }
    results.append(row)
    print(json.dumps(row), flush=True)

    (OUT_DIR / "raw-data" / f"n_policies_{n_policies}_status.txt").write_text(
        kubectl(f"-n {namespace} get runtimesecuritypolicy -o wide", check=False).stdout
    )

    if row["saturated"]:
        print(f"SATURATION POINT reached at N_policies={n_policies}: "
              f"only {active_count}/{n_policies} reached active within {timeout_s}s", flush=True)

    # Clean up this level's objects once measured: leaving them around would
    # make every subsequent N-level (and any other campaign sharing this
    # cluster, e.g. the revocation script) reconcile against an
    # ever-growing pile of leftover RuntimeSecurityPolicy objects, since the
    # agent's reconcile loop lists ALL policies cluster-wide every cycle --
    # confirmed to starve a concurrently-running revocation campaign's tight
    # timing windows during this run.
    kubectl(f"delete namespace {namespace} --ignore-not-found", capture=False)

csv_path = OUT_DIR / "raw-data" / "scalability-policies-results.csv"
with open(csv_path, "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
    writer.writeheader()
    writer.writerows(results)
print(f"results written to {csv_path}")
