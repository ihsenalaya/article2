# Azure AI Foundry -- used ONLY to retrieve model weights (see
# deploy/azure/scripts/fetch-foundry-model.sh). Never used as an inference
# endpoint: inference is always self-hosted on our own AKS pods, per the
# mission's non-negotiable rule. This resource exists purely so the model
# catalog / weight download path is real Azure AI Foundry, not a
# substitute.

resource "azurerm_cognitive_account" "foundry" {
  name                = "ais-${local.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  kind                = "AIServices"
  sku_name            = "S0"
  tags                = local.tags
}

resource "azurerm_ai_foundry" "main" {
  name                  = "aif-${local.name_prefix}"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  storage_account_id    = azurerm_storage_account.results.id
  key_vault_id          = azurerm_key_vault.main.id
  container_registry_id = azurerm_container_registry.main.id

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}

resource "azurerm_ai_foundry_project" "main" {
  name               = "proj-${local.name_prefix}"
  location           = azurerm_ai_foundry.main.location
  ai_services_hub_id = azurerm_ai_foundry.main.id

  identity {
    type = "SystemAssigned"
  }

  tags = local.tags
}
