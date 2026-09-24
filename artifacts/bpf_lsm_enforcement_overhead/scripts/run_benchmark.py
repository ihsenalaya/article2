#!/usr/bin/env python3
"""BPF-LSM enforcement-path microbenchmark orchestration.

Requires scripts/setup.sh to have run first and exported: BENCH_POD,
BENCH_POD_UID, AGENT_POD, AGENT_NS, CGROUP_ID, POLICY_GENERATION,
WORKER_NODE, NS (and KUBECONFIG).

For each of 3 operation classes (exec, file, network), runs N_BLOCKS
randomized paired blocks of {C0, C1, C2, C3}. C1/C2/C3 order is freely
randomized per block (cheap: one local-filesystem control-channel round
trip, no restart). C0 requires actually detaching the relevant BPF-LSM hook
node-wide, so its position (before or after the C1-3 triplet) is decided by
an independent coin flip per block rather than interleaved mid-triplet --
see README.md's Methodology section for why.

Writes raw_results.jsonl (one line per individual measurement) and archives
periodic bpftool ground-truth snapshots into validation/.
"""
import json
import os
import random
import subprocess
import sys
import time
from datetime import datetime, timezone

REPO_ROOT = os.environ.get("REPO_ROOT", os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
TF_DIR = f"{REPO_ROOT}/deploy/azure/cpu-campaign-20260813"
OUT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_PATH = os.path.join(OUT_DIR, "raw_results.jsonl")
VALIDATION_DIR = os.path.join(OUT_DIR, "validation")

NS = os.environ["NS"]
BENCH_POD = os.environ["BENCH_POD"]
BENCH_POD_UID = os.environ["BENCH_POD_UID"]
AGENT_POD = os.environ["AGENT_POD"]
AGENT_NS = os.environ["AGENT_NS"]
CGROUP_ID = os.environ["CGROUP_ID"]
POLICY_GENERATION = os.environ["POLICY_GENERATION"]
WORKER_NODE = os.environ["WORKER_NODE"]

SEED = int(os.environ.get("BENCH_SEED", "20260817"))
random.seed(SEED)
N_BLOCKS = int(os.environ.get("BENCH_N_BLOCKS", "30"))

SSH_KEY = os.path.expanduser("~/.ssh/article2_cpucampaign_ed25519")


def tf_output(name):
    r = subprocess.run(
        ["terraform", f"-chdir={TF_DIR}", "output", "-raw", name],
        capture_output=True, text=True, check=True,
    )
    return r.stdout.strip()


WORKER_IP = tf_output("worker_public_ip")

OPS = {
    "exec": {"hook": "exec", "n": 2000, "prog": "lsm_exec"},
    "file": {"hook": "file", "n": 20000, "prog": "lsm_file_open"},
    "network": {"hook": "connect", "n": 5000, "prog": "lsm_connect"},
}
MODE_NAMES = {0: "C3", 1: "C1", 2: "C2"}  # benchmark_mode value -> condition name (C0 has no mode, it's detach)


def sh(cmd, timeout=30):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout.strip(), r.stderr.strip()


def kubectl_exec(pod, ns, container_cmd, timeout=60):
    # The agent's own image is distroless (no shell) -- container_cmd is
    # passed as literal argv, not a shell string, everywhere this is used
    # against AGENT_POD (see send_bench_cmd). The perf-workload image
    # (BENCH_POD) DOES have a shell, but its own call sites here only ever
    # invoke /perf-workload directly, so this stays shell-free uniformly.
    args = " ".join(container_cmd) if isinstance(container_cmd, list) else container_cmd
    cmd = f"kubectl -n {ns} exec {pod} -- {args}"
    return sh(cmd, timeout=timeout)


def ssh_worker(remote_cmd, timeout=20):
    cmd = f"ssh -o StrictHostKeyChecking=accept-new -i {SSH_KEY} azureuser@{WORKER_IP} {json.dumps(remote_cmd)}"
    return sh(cmd, timeout=timeout)


def send_bench_cmd(cmd_str, timeout=15):
    # /agent bench-cmd is this same binary acting as its own control-client
    # (see cmd/agent/main.go's "bench-cmd" subcommand doc comment) --
    # required because the agent's distroless image has no shell for a
    # `sh -c '...'`-based client to run in.
    rc, out, err = kubectl_exec(AGENT_POD, AGENT_NS, ["/agent", "bench-cmd", cmd_str], timeout=timeout)
    return rc, out, err


def detach_hook(hook):
    rc, out, err = send_bench_cmd(f"detach {hook}")
    if rc != 0 or out != "OK":
        raise RuntimeError(f"detach {hook} failed: rc={rc} out={out!r} err={err!r}")


def reattach_hook(hook):
    rc, out, err = send_bench_cmd(f"reattach {hook}")
    if rc != 0 or out != "OK":
        raise RuntimeError(f"reattach {hook} failed: rc={rc} out={out!r} err={err!r}")


def set_benchmark_mode(mode):
    rc, out, err = send_bench_cmd(f"setmode {CGROUP_ID} {mode}")
    if rc != 0 or out != "OK":
        raise RuntimeError(f"setmode {mode} failed: rc={rc} out={out!r} err={err!r}")


def validate_link(prog_name, expect_attached, retries=2):
    # `bpftool link list` identifies the target program only by numeric ID
    # ("prog <id>"), never by name -- unlike `bpftool prog list`, which does
    # print `name lsm_exec` etc. Resolve the name to its current prog ID
    # first, then check whether that ID appears in the link list.
    last_count = None
    for attempt in range(retries + 1):
        rc, prog_out, err = ssh_worker(f"sudo bpftool -j prog list")
        if rc != 0:
            raise RuntimeError(f"validation FAILED: bpftool prog list error: {err}")
        progs = json.loads(prog_out)
        matches = [p["id"] for p in progs if p.get("name") == prog_name]
        if not matches:
            raise RuntimeError(f"validation FAILED: no loaded program named {prog_name} (was it ever loaded?)")
        prog_id = matches[0]

        rc, link_out, err = ssh_worker(f"sudo bpftool -j link list")
        if rc != 0:
            raise RuntimeError(f"validation FAILED: bpftool link list error: {err}")
        links = json.loads(link_out)
        last_count = sum(1 for l in links if l.get("prog_id") == prog_id)
        attached = last_count > 0
        if attached == expect_attached:
            return attached
        if attempt < retries:
            time.sleep(0.2)
    raise RuntimeError(
        f"validation FAILED: {prog_name} (prog_id={prog_id}) attachment mismatch, expected attached={expect_attached}, link count={last_count}"
    )


def validate_cgroup_config(expect_benchmark_mode):
    rc, out, err = ssh_worker("sudo bpftool map dump name cgroup_configs")
    if rc != 0:
        raise RuntimeError(f"validation FAILED: bpftool map dump error: {err}")
    try:
        entries = json.loads(out)
    except Exception as e:
        raise RuntimeError(f"validation FAILED: could not parse bpftool map dump: {e}, raw={out!r}")
    for entry in entries:
        if str(entry["key"]) == str(CGROUP_ID):
            actual = entry["value"]["benchmark_mode"]
            if actual != expect_benchmark_mode:
                raise RuntimeError(
                    f"validation FAILED: cgroup_configs[{CGROUP_ID}].benchmark_mode={actual}, expected {expect_benchmark_mode}"
                )
            return entry
    raise RuntimeError(f"validation FAILED: no cgroup_configs entry for cgroup {CGROUP_ID}")


def snapshot_validation(tag):
    rc1, out1, _ = ssh_worker("sudo bpftool link list")
    rc2, out2, _ = ssh_worker("sudo bpftool map dump name cgroup_configs")
    path = os.path.join(VALIDATION_DIR, f"snapshot-{tag}.txt")
    with open(path, "w") as f:
        f.write("=== bpftool link list ===\n" + out1 + "\n\n")
        f.write("=== bpftool map dump cgroup_configs ===\n" + out2 + "\n")


def run_perf_workload(op, n):
    rc, out, err = kubectl_exec(BENCH_POD, NS, f"/perf-workload --op={op} --n={n}", timeout=120)
    if rc != 0 or not out:
        return None, f"kubectl exec failed rc={rc} err={err}"
    try:
        return json.loads(out.strip().splitlines()[-1]), None
    except Exception as e:
        return None, f"parse error: {e} raw={out!r}"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def measure(op, condition, block_id, out_f):
    spec = OPS[op]
    hook, n, prog = spec["hook"], spec["n"], spec["prog"]
    excluded = False
    exclusion_reason = ""
    kernel_result = "0"

    try:
        if condition == "C0":
            detach_hook(hook)
            validate_link(prog, expect_attached=False)
        else:
            mode = {"C1": 1, "C2": 2, "C3": 0}[condition]
            set_benchmark_mode(mode)
            validate_link(prog, expect_attached=True)
            if condition in ("C2", "C3"):
                validate_cgroup_config(mode)

        result, err = run_perf_workload(op, n)
        if err or result is None:
            excluded = True
            exclusion_reason = f"perf-workload failed: {err}"
            result = {}
    except Exception as e:
        excluded = True
        exclusion_reason = str(e)
        result = {}
    finally:
        if condition == "C0":
            try:
                reattach_hook(hook)
                validate_link(prog, expect_attached=True)
            except Exception as e:
                excluded = True
                exclusion_reason = (exclusion_reason + "; " if exclusion_reason else "") + f"reattach failed: {e}"
        else:
            try:
                set_benchmark_mode(0)  # restore production mode between conditions
            except Exception:
                pass

    n_completed = result.get("n_completed", 0)
    n_errors = result.get("n_errors", 0)
    usec_per_op = result.get("usec_per_op_cpu_total", None)

    # network's ALLOW-authorized connect() is intentionally to 127.0.0.1:1
    # (nothing listens there): every attempt reaches the TCP layer and gets
    # ECONNREFUSED there -- n_errors == n is the EXPECTED, deterministic
    # outcome, isolating BPF-LSM hook cost from RTT/handshake cost, same
    # convention already established and defended by the existing F1
    # experiment (see ../../performance/experiment-config.json). Do not
    # treat this as a measurement failure.
    op_succeeded = True
    if op != "network" and n_errors > 0:
        op_succeeded = False
        if not excluded:
            excluded = True
            exclusion_reason = f"unexpected operation errors: n_errors={n_errors}/{n}"

    row = {
        "operation_class": op,
        "block_id": block_id,
        "condition": condition,
        "timestamp": now_iso(),
        "usec_per_op_cpu_total": usec_per_op,
        "n": n,
        "n_completed": n_completed,
        "n_errors": n_errors,
        "operation_succeeded": op_succeeded,
        "kernel_return_value_note": "0 (allow) expected for every condition -- this experiment is ALLOW-only, per experiment protocol scope",
        "pod_uid": BENCH_POD_UID,
        "cgroup_id": CGROUP_ID,
        "policy_generation": POLICY_GENERATION,
        "bpf_lsm_active_check": "bpf in /sys/kernel/security/lsm, confirmed at setup -- see validation/",
        "node_id": WORKER_NODE,
        "kernel": "6.8.0-1064-azure",
        "excluded": excluded,
        "exclusion_reason": exclusion_reason,
    }
    out_f.write(json.dumps(row) + "\n")
    out_f.flush()
    return row


def run_block(op, block_id, out_f):
    order = ["C1", "C2", "C3"]
    random.shuffle(order)
    c0_before = random.random() < 0.5
    sequence = (["C0"] + order) if c0_before else (order + ["C0"])
    rows = []
    for cond in sequence:
        rows.append(measure(op, cond, block_id, out_f))
    return rows


def main():
    os.makedirs(VALIDATION_DIR, exist_ok=True)
    mode = sys.argv[1] if len(sys.argv) > 1 else "full"
    n_blocks = 2 if mode == "smoke" else N_BLOCKS

    with open(RAW_PATH, "a") as out_f:
        for op in ["exec", "file", "network"]:
            print(f"=== {op}: {n_blocks} blocks ===", file=sys.stderr)
            snapshot_validation(f"{op}-start")
            for block_id in range(1, n_blocks + 1):
                t0 = time.time()
                rows = run_block(op, block_id, out_f)
                excluded_count = sum(1 for r in rows if r["excluded"])
                print(
                    f"  block {block_id}/{n_blocks} ({time.time()-t0:.1f}s, {excluded_count} excluded)",
                    file=sys.stderr,
                )
            snapshot_validation(f"{op}-end")


if __name__ == "__main__":
    main()
