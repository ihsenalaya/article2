# Task 02 — Software Bill of Materials / Baseline Deployment

Git commit built and deployed: `3268c182a5dcccc8dd8d286f32e96f8ce7770505`.

## Container images (built via `az acr build`, ACR `acrarticle2ebpftm2ogg`, remote build — see rationale below)

| Component | Image | Digest | Base build image (resolved) |
|---|---|---|---|
| Operator | `acrarticle2ebpftm2ogg.azurecr.io/runtime-guard-operator:cpu-campaign-20260813` | `sha256:c1303d0e81d811bbd7c9caf894c3c04662d8ffe134a9a24e9d71e69f99076e08` | `golang:1.21` → `sha256:4746d26432a9117a5f58e95cb9f954ddf0de128e9d5816886514199316e4a2fb` |
| eBPF agent | `acrarticle2ebpftm2ogg.azurecr.io/runtime-guard-ebpf-agent:cpu-campaign-20260813` | `sha256:259f2d77e8ee33b855e4b48c5087662a602f6b139918729a108a003367213320` | `golang:1.25` → `sha256:dbeddb5e728ea4b5ba7920574413e311025ffa42d196793857e4d160e8dfe60d` |

Runtime base for both: `gcr.io/distroless/static:nonroot` →
`sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6`.

Both images built from an unmodified checkout of the exact commit above — no source changes in
this task (rule: only implementation changes required for valid measurement are made, and Task 02
makes none).

**Why `az acr build` instead of local `docker build`**: this execution environment has no
`docker` daemon available (Docker Desktop's WSL integration is not enabled for this distro) and
no local `clang`/LLVM (not needed here — see below). `az acr build` uploads the build context and
builds remotely in Azure using the project's existing ACR (`acrarticle2ebpftm2ogg`, already
provisioned in `rg-article2-ebpf-20260801` from an earlier phase of this project — not a new
resource, and not touched/modified by this campaign's Task 01 resource group). This is a normal,
documented ACR Tasks feature, not a workaround of anything security-relevant.

## Go toolchain

- Local `go`: `go1.26.5 linux/amd64` (used to run `go build ./...` and the full test suites
  locally; both modules build cleanly with it — newer than each module's `go.mod` directive,
  which is compatible).
- Operator module (`operator/go.mod`): `go 1.21` (matches the Dockerfile's `golang:1.21` builder).
- eBPF-agent module (`ebpf-agent/go.mod`): `go 1.25.0` (matches the Dockerfile's `golang:1.25`
  builder).

## Key dependency versions

- `github.com/cilium/ebpf` v0.22.0 (eBPF loader/ringbuf library, ebpf-agent).
- `sigs.k8s.io/controller-runtime` v0.17.0 (both modules).
- `k8s.io/api`, `k8s.io/apimachinery`, `k8s.io/client-go` v0.29.0.
- `github.com/onsi/ginkgo/v2` v2.14.0 / `github.com/onsi/gomega` v1.30.0 (operator test suite).

## eBPF/BPF compiler toolchain (clang/LLVM/libbpf)

**Not rebuilt in this task.** The compiled BPF object
(`ebpf-agent/internal/bpfobjs/agent_x86_bpfel.o`, embedded via `//go:embed` into the committed
bpf2go-generated Go bindings) was last regenerated in a prior phase of this project and has not
changed since — confirmed by `git log -1 -- ebpf-agent/internal/bpfobjs/agent_x86_bpfel.o` →
commit `d0798b7c` (2026-08-08), well before this campaign's HEAD, and its current on-disk SHA-256
(`612bb56034545cb83c5daecdccd273c5caca87081422b83eba5e9572bdca1f25`) matches what is committed —
i.e. this task built and deployed the *exact same* eBPF object bytes the repository has carried
since 2026-08-08, not a locally-regenerated one. The historically recorded builder toolchain
(`EXPERIMENTS_LOG.md` line 423, Phase 4) was: **clang 14.0.0, llvm-config 14, libbpf-dev 0.5.0**.
This is a historical record, not something re-verified in this session — CO-RE portability
(field offsets resolved against the target kernel's BTF at load time, not baked in at compile
time) is exactly why the object does not need to be, and was not, recompiled for this new
cluster. If Task 03/05/06/11 require changes to `agent.bpf.c` (e.g. adding drop counters), that
task's own review must record the actual clang/LLVM/libbpf versions used for that rebuild, not
reuse this note.

`bpf2go` invocation (unchanged, `ebpf-agent/internal/bpfobjs/gen.go`):
```
go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 \
  -type event -type cgroup_config -type path_rule_key -type net_rule_key -type rule_action \
  Agent ../../bpf/agent.bpf.c -- -I../../bpf -I../../bpf/headers -O2 -g -D__TARGET_ARCH_x86
```

## Test results (rule: run all existing unit/integration/CRD validation/verifier tests; do not
silently bypass failures)

All raw output in `artifacts/baseline/test-results/`.

- **ebpf-agent** (`go test ./...`): **32/32 tests PASS**, 0 failures, across
  `cmd/agent` (2 tests — `TestMarkPolicyEnforcementReady`, `TestEmitEvidenceBindsDecisionPolicyMonitorAndFreshness`),
  `internal/cgroupmap` (10 tests), `internal/lsmdetect` (7 tests), `internal/mediation` (1 test —
  the observation-coverage-matrix traceability test), `internal/pathhash` (4 tests),
  `internal/policy` (12 tests). Log: `ebpf-agent-go-test.log`.
- **operator** (`make test`, includes `manifests`/`generate`/`fmt`/`vet` + `go test` with
  **envtest** — a real embedded etcd + kube-apiserver, not a mock): **all packages PASS**, notably
  `internal/controller` (the full controller integration suite — signature verification,
  anti-replay, policy derivation, CRD validation via the real API server's OpenAPI/CEL
  validation) at **77.0% coverage**, `pkg/token` 78.6%, `pkg/evidence` 68.8%, `pkg/crypto` 64.6%,
  `cmd/verify-evidence` 64.8% (the offline evidence verifier's own test suite),
  `cmd/runtime-guard-launcher` 15.1%. `go vet` clean. Log: `operator-go-test.log`.
- No test was skipped, weakened, or worked around. No failures occurred to bypass.

## Deployment (Task 02's "deploy RuntimeGuard")

Deployed onto the Task 01 cluster (`deploy/azure/cpu-campaign-20260813`) via
`scripts/deploy-runtimeguard.sh`: CRDs (2 owned + 1 vendored upstream mirror), 3 namespaces,
Operator Deployment (1/1 Running), eBPF-agent DaemonSet (2/2 Running — both nodes, audit mode,
matches Task 01's LSM finding). Fresh Ed25519 keypairs generated via `operator/cmd/gen-keypair`
for (a) the trust-anchor (simulates article 1's scheduler signing key — public half in a
ConfigMap the Operator verifies against) and (b) the agent's evidence-signing key (private half
in a Secret consumed by the DaemonSet). Private key material lives only in
`deploy/azure/cpu-campaign-20260813/.run/secrets/*.env` (gitignored) and in-cluster Secrets —
never committed. Full state capture: `artifacts/baseline/deployment-state/`.

**Note on the ACR pull-secret refresh token**: image pulls use a short-lived (~3h) AAD refresh
token (`az acr login --expose-token`), not a long-lived credential — chosen to avoid creating a
new standing credential/identity resource for this. Both node's containerd already have the
images cached locally as of this task, so subsequent pod reschedules on the *same* nodes do not
need a fresh pull. If a later task needs a fresh pull after the token expires (e.g. after a node
reboot in Task 10), rerun `scripts/deploy-runtimeguard.sh` to mint a new token.

**Bug found and fixed during this task (not a RuntimeGuard bug — a deployment tooling bug)**: the
first `deploy-runtimeguard.sh` run produced `ImagePullBackOff` on all pods with a `401
Unauthorized` from ACR's OAuth token endpoint. Root cause: the Windows-hosted `az` CLI
(`/mnt/c/Program Files/Microsoft SDKs/Azure/CLI2/wbin/az`, invoked from this WSL shell) emits
CRLF line endings; bash `$(...)` command substitution only strips the trailing `\n`, leaving a
stray `\r` embedded at the end of the captured token, corrupting it. Fixed by piping through
`tr -d '\r\n'` when capturing the token. Documented here rather than silently worked around,
per the protocol's "no silent workarounds" discipline (rule applies primarily to the
RuntimeGuard implementation itself, but the same standard applies to this campaign's own tooling
bugs).
