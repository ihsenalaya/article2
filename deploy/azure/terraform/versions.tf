terraform {
  required_version = ">= 1.9.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.15"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 3.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.12"
    }
  }

  # State is local by design for this project: a single researcher, a single
  # machine, no team to coordinate with. If this project ever needs shared
  # state, migrate to an azurerm backend explicitly rather than defaulting to
  # one nobody asked for.
}

provider "azurerm" {
  features {
    resource_group {
      # Never let `terraform destroy` silently give up because the RG has
      # leftover resources it doesn't manage — the mission's teardown
      # script relies on this actually deleting everything.
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azuread" {}
