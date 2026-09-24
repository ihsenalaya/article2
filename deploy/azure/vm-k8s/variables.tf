variable "location" {
  description = "Azure region for the CPU VM Kubernetes cluster."
  type        = string
  default     = "eastus2"
}

variable "name_prefix" {
  description = "Short prefix used for all Azure resource names."
  type        = string
  default     = "a2-vmk8s-20260808"
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
  description = "CIDR allowed to access SSH and the Kubernetes API. Prefer a single /32 workstation IP."
  type        = string
}

variable "control_plane_vm_size" {
  description = "Low-cost VM size for the Kubernetes control plane."
  type        = string
  default     = "Standard_D2s_v7"
}

variable "worker_vm_size" {
  description = "Low-cost VM size for the CPU Kubernetes worker."
  type        = string
  default     = "Standard_D2s_v7"
}

variable "project" {
  description = "Required Azure tag: project."
  type        = string
  default     = "these-article2"
}

variable "purpose" {
  description = "Required Azure tag: purpose."
  type        = string
  default     = "vm-kubernetes-ebpf-runtime-experiments"
}

variable "owner" {
  description = "Required Azure tag: owner."
  type        = string
  default     = "ihsen-alaya"
}

variable "environment" {
  description = "Required Azure tag: environment."
  type        = string
  default     = "research-task13"
}

variable "created_by" {
  description = "Required Azure tag: created-by."
  type        = string
  default     = "codex"
}

variable "expires" {
  description = "Required Azure tag: expires."
  type        = string
  default     = "2026-08-15"
}
