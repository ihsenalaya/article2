variable "location" {
  description = "Azure region for the CPU VM Kubernetes cluster. Matches the prior CPU campaign (deploy/azure/vm-k8s) for comparability."
  type        = string
  default     = "eastus2"
}

variable "name_prefix" {
  description = "Short prefix used for all Azure resource names, including the dedicated resource group name (rg-<name_prefix>)."
  type        = string
  default     = "a2-cpucampaign-20260813"
}

variable "admin_username" {
  description = "Linux admin username for SSH."
  type        = string
  default     = "azureuser"
}

variable "ssh_public_key" {
  description = "SSH public key authorized on both VMs."
  type        = string
  sensitive   = true
}

variable "allowed_ssh_cidr" {
  description = "CIDR allowed to access SSH and the Kubernetes API. Single /32 workstation IP."
  type        = string
}

variable "control_plane_vm_size" {
  description = "Low-cost CPU-only VM size for the Kubernetes control plane. Standard_D2s_v5 is not offered to this subscription in eastus2 (see artifacts/azure/cost-preflight.md); Standard_D2s_v7 is the closest available equivalent and is what the prior CPU campaign actually used successfully."
  type        = string
  default     = "Standard_D2s_v7"
}

variable "worker_vm_size" {
  description = "Low-cost CPU-only VM size for the Kubernetes worker. See control_plane_vm_size doc."
  type        = string
  default     = "Standard_D2s_v7"
}

variable "auto_shutdown_time" {
  description = "Daily auto-shutdown time (HHmm, VM-local/UTC per timezone below) as a cost-protection backstop (experiment protocol rule 14)."
  type        = string
  default     = "2300"
}

variable "auto_shutdown_timezone" {
  description = "Timezone for the auto-shutdown schedule."
  type        = string
  default     = "UTC"
}

variable "project" {
  description = "Required Azure tag: project."
  type        = string
  default     = "article2-cpu-campaign"
}

variable "purpose" {
  description = "Required Azure tag: purpose."
  type        = string
  default     = "q1-scientific-hardening-cpu-experiments"
}

variable "owner" {
  description = "Required Azure tag: owner."
  type        = string
  default     = "ihsen-alaya"
}

variable "environment" {
  description = "Required Azure tag: environment."
  type        = string
  default     = "research-cpu-campaign-20260813"
}

variable "created_by" {
  description = "Required Azure tag: created-by."
  type        = string
  default     = "terraform"
}

variable "expires" {
  description = "Required Azure tag: expires (informational; actual teardown is via terraform destroy, see Task 19)."
  type        = string
  default     = "2026-08-20"
}
