# Azure VM Kubernetes Infrastructure

TASK-13 uses this directory for a reproducible, VM-based Kubernetes cluster.
It deliberately does not use AKS and deliberately provisions no H100 resources.

## Topology

- Resource group, VNet, subnet, NSG, NICs, public IPs and OS disks managed by Terraform.
- One Ubuntu 22.04 control-plane VM.
- One Ubuntu 22.04 CPU worker VM.
- Kubernetes installed with kubeadm, containerd and Calico by versioned scripts.
- Default VM size is `Standard_D2s_v7`, selected after `Standard_B2s` was rejected by eastus2 capacity restrictions in this subscription.

## Required tags

Every Azure resource uses:

- `project`
- `purpose`
- `owner`
- `environment`
- `created-by`
- `expires`

## Workflow

```bash
cd deploy/azure/vm-k8s
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` with:

- `allowed_ssh_cidr`: preferably your workstation public IP as `/32`.
- `ssh_public_key`: the public half of a dedicated SSH key.

Then run:

```bash
terraform init
terraform plan -out task13.tfplan
terraform apply task13.tfplan
SSH_KEY="$HOME/.ssh/id_ed25519" ./scripts/bootstrap-cluster.sh
OUT_DIR="$(pwd)/.run/validation" ./scripts/validate-cluster.sh
```

The kubeconfig is written to `deploy/azure/vm-k8s/.run/kubeconfig`.

## Validation scope

`scripts/validate-cluster.sh` records:

- `kubectl get nodes`
- `kubectl get pods -A`
- kube-system CNI workloads
- containerd and kubelet versions
- kernel and OS image
- cgroup mode
- LSM configuration
- kernel BPF feature probe

## Teardown

```bash
cd deploy/azure/vm-k8s
terraform destroy
```

Only resources in `rg-a2-vmk8s-20260808` are managed by this module.
