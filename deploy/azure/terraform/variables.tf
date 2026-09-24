variable "location" {
  description = "Azure region. eastus2 confirmed (2026-08-01, real az cli query) to offer Standard_NCC40ads_H100_v5 (confidential H100) with 40/40 vCPU quota available in this subscription -- exactly enough for one node."
  type        = string
  default     = "eastus2"
}

variable "date_code" {
  description = "Date this environment was created, used in resource naming/tags so leftover resources are easy to identify and age out. Format YYYYMMDD."
  type        = string
}

variable "owner" {
  description = "Tag: who owns this environment (rule: every Azure resource must be tagged owner=<user>)."
  type        = string
  default     = "ihsen-alaya"
}

variable "ttl" {
  description = "Tag: intended lifetime of this environment before manual/automatic teardown. Informational -- the actual enforcement is deploy/azure/scripts/safety-timeout.sh, not this tag."
  type        = string
  default     = "72h"
}

variable "enable_gpu_pool" {
  description = "Whether to create the confidential H100 GPU node pool. Deliberately defaults to false: rule 5 requires GPU resources to exist only during active measurement campaigns. Set true only for the duration of a real measurement run (Phase 9), then back to false before terraform apply again."
  type        = bool
  default     = false
}

variable "gpu_node_count" {
  description = "Node count for the confidential GPU pool when enabled. Kept as a variable (not hardcoded 1) so scale-down-to-0-without-destroy is possible via `terraform apply -var gpu_node_count=0` as a faster alternative to the full teardown script."
  type        = number
  default     = 1

  validation {
    condition     = var.gpu_node_count >= 0 && var.gpu_node_count <= 1
    error_message = "Subscription quota for StandardNCCads2023Family in eastus2 is 40 vCPUs = exactly 1 node of Standard_NCC40ads_H100_v5 (40 vCPUs each). Requesting more will fail at apply time with a real Azure quota error, not a fabricated one -- raise quota first if more nodes are ever needed."
  }
}

variable "alert_email" {
  description = "Email address for the budget alert action group."
  type        = string
}

variable "budget_amount_usd" {
  description = "Monthly budget ceiling in USD for the resource group. Alerts fire at 50/80/100% of this; it does not itself stop spend -- see deploy/azure/scripts/safety-timeout.sh for that."
  type        = number
  default     = 200
}
