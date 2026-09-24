# Azure IaC — Phase 7-10

Fully isolated from any other Azure infrastructure in this subscription
(see `EXPERIMENTS_LOG.md` Phase 7 — there is an unrelated
`rg-article2-governance-20260708` managed by a different tool for a
different project; this Terraform never reads, imports, or touches it).

## What this provisions

- Resource group `rg-article2-ebpf-<date_code>` (eastus2), tagged
  `project=these-article2, owner=<owner>, ttl=<ttl>`.
- VNet/subnet, AKS cluster (2-node `Standard_D4s_v5` system pool).
- A confidential H100 GPU node pool (`Standard_NCC40ads_H100_v5`),
  **disabled by default** (`enable_gpu_pool = false`) — created only for
  the duration of an actual measurement campaign (Phase 9).
- ACR (for pushing locally-built images — builds themselves always happen
  locally, per the mission's non-negotiable rule; this is distribution
  only), a storage account for results, a Key Vault, an Azure AI Foundry
  hub + project (model weight retrieval only — never an inference
  endpoint), a budget alert, and a dedicated least-privilege automation
  service principal (scoped to just this resource group).

## Verified facts (real `az cli`/API queries, 2026-08-01 — not assumed)

- `Standard_NCC40ads_H100_v5` (1× H100, AMD SEV-SNP confidential VM, 40
  vCPUs, 320GB RAM) is available in **eastus2**.
- This subscription's `StandardNCCads2023Family` quota in eastus2 is
  **40/40 vCPUs** — exactly enough for **one** node, no quota-increase
  request needed. Asking Terraform for more than 1 node will fail with a
  real Azure quota error (enforced by a `variable` validation block, not
  discovered the hard way at apply time).
- Azure Retail Prices API, eastus2: `Standard_NCC40ads_H100_v5` on-demand =
  **$8.82/hour** (Spot ≈ $1.63-1.79/hour, but evictable — not used by
  default for a controlled measurement campaign). `Standard_D4s_v5` (system
  pool, ×2 nodes) ≈ $0.192/hour each.

## Workflow

```
cd deploy/azure/terraform
cp terraform.tfvars.example terraform.tfvars   # fill in your email etc.
terraform init
terraform plan          # read-only, no cost -- always run this before apply
```

**`terraform apply` for the base environment (no GPU) requires no special
confirmation beyond normal care** — nothing billed is expensive at this
stage (AKS system pool + storage + ACR + Key Vault + Foundry hub, all
low-cost). **Enabling `enable_gpu_pool = true` and applying it is the
mission's mandatory human checkpoint (Phase 8)** — do not do this without
having stopped, summarized cost/duration, and gotten explicit confirmation
first.

Once the GPU pool is up for a real measurement window:

```
nohup deploy/azure/scripts/safety-timeout.sh 6 > /tmp/safety-timeout.log 2>&1 &
echo $! > /tmp/safety-timeout.pid   # so it can be cancelled if you finish early
```

When the campaign ends (before the timeout, ideally):

```
deploy/azure/scripts/scale-down-gpu.sh     # removes just the GPU pool
kill "$(cat /tmp/safety-timeout.pid)"      # cancel the now-unnecessary watchdog
```

Full environment teardown (Phase 10, end of all Azure work):

```
deploy/azure/scripts/teardown-full.sh      # destroys everything, asks for confirmation
```

## Model weights

`deploy/azure/scripts/fetch-foundry-model.sh` downloads weights from the
Azure AI Foundry model catalog (reuse-if-exists-else-fetch — safe to
re-run). Weights are used for self-hosted inference on our own AKS pods
only; this project never creates or calls an Azure-hosted inference
endpoint for these models.
