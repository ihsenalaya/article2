# RuntimeGuard — Attestation-Bound Runtime Enforcement with eBPF for AI Workloads

RuntimeGuard binds a verified, signed placement decision for an AI workload to
runtime enforcement on the node that actually runs it. A Kubernetes operator
turns each verified `AIPlacementDecision` into a `RuntimeSecurityPolicy`; a
node-level eBPF agent enforces that policy on the pod's cgroup (execve, file
open, connect, device open) through BPF-LSM, and emits signed
`RuntimePlacementEvidence` describing what actually happened.

## Repository layout

| Path | Contents |
|---|---|
| `operator/` | Kubebuilder operator (`aiops.imperium.io/v1alpha1` CRDs, controllers, token/evidence/crypto packages, evidence verifier) |
| `ebpf-agent/` | Node agent (Go + cilium/ebpf) and the BPF-LSM program (`bpf/agent.bpf.c`) |
| `deploy/kind/` | Reproducible local kind lab (create / validate / destroy) |
| `deploy/azure/` | Terraform and scripts for the Azure environments (CPU kubeadm cluster, confidential GPU VM) |
| `experiments/` | Workload manifests, attack scenarios and measurement scripts |
| `artifacts/` | Experiment results: raw data, processed CSVs, scripts, summaries and exclusions per experiment |
| `DESIGN.md` | CRD design decisions |

## Quick start (kind)

Requirements: Go, Docker, kind, kubectl, clang/llvm 14 (to regenerate the eBPF objects).

```sh
deploy/kind/gen-trust-anchor.sh
deploy/kind/create-lab.sh     # creates cluster "article2", builds and loads images, deploys everything
deploy/kind/validate-lab.sh
deploy/kind/destroy-lab.sh
```

On kernels where `bpf` is not in the active LSM list (`/sys/kernel/security/lsm`),
the agent runs in audit mode and reports `evidenceMode=simulated`.

## Tests

```sh
cd operator && make envtest && ./bin/setup-envtest-latest use 1.29.0 --bin-dir ./bin && go test ./...
cd ebpf-agent && go test ./...
```

## Results

Start with [`artifacts/EXPERIMENTS_MASTER_REPORT.md`](artifacts/EXPERIMENTS_MASTER_REPORT.md).
Each directory under `artifacts/experiments/` holds `README.md`, `summary.md`,
`exclusions.md`, `raw/`, `processed/` and `scripts/` for one experiment
(admission-to-release closure, observation completeness, revocation, pod
recreation, scale, performance, BPF-LSM enforcement, control-plane tampering).
`artifacts/bpf_lsm_enforcement_overhead/` contains the BPF-LSM enforcement
overhead benchmark.

Experiment scripts resolve the repository root with `git rev-parse` (override
with `REPO_ROOT=...`) and write new runs under `results/`.
