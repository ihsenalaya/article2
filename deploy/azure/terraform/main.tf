data "azurerm_client_config" "current" {}

locals {
  # Fully isolated from the pre-existing rg-article2-governance-20260708
  # (a different tool's Terraform state, different project -- see
  # EXPERIMENTS_LOG.md Phase 7 and DESIGN.md). Never reused, never imported.
  name_prefix = "article2-ebpf-${var.date_code}"

  tags = {
    project = "these-article2"
    owner   = var.owner
    ttl     = var.ttl
    purpose = "ebpf-runtime-enforcement-evaluation"
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.tags
}

# --- Networking -------------------------------------------------------

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${local.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.20.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "aks" {
  name                 = "snet-aks"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.20.0.0/20"]
}

# --- Container registry (for pushing locally-built images -- rule 2:
# builds always happen locally, this is distribution only, never a
# remote/Azure-side build) ---------------------------------------------

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_container_registry" "main" {
  name                = "acrarticle2ebpf${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

# --- Storage for experiment results (evidence exports, measurement CSVs) ---

resource "azurerm_storage_account" "results" {
  name                     = "starticle2ebpf${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  tags                     = local.tags
}

resource "azurerm_storage_container" "results" {
  name                  = "results"
  storage_account_id    = azurerm_storage_account.results.id
  container_access_type = "private"
}

# --- Key Vault (own, isolated -- never the article2-governance one) ------

resource "azurerm_key_vault" "main" {
  name                       = "kv-a2ebpf${random_string.suffix.result}"
  location                   = azurerm_resource_group.main.location
  resource_group_name        = azurerm_resource_group.main.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  tags                       = local.tags
}

resource "azurerm_key_vault_access_policy" "current_user" {
  key_vault_id = azurerm_key_vault.main.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
}
