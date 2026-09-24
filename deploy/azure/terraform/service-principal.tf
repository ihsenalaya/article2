# Dedicated, least-privilege service principal for unattended automation
# (the safety-timeout teardown watchdog, measurement scripts) -- scoped to
# ONLY this resource group, never subscription-wide, per rule 5.

resource "azuread_application" "automation" {
  display_name = "sp-${local.name_prefix}"
}

resource "azuread_service_principal" "automation" {
  client_id = azuread_application.automation.client_id
}

resource "time_rotating" "sp_password_rotation" {
  rotation_days = 30
}

resource "azuread_service_principal_password" "automation" {
  service_principal_id = azuread_service_principal.automation.id
  rotate_when_changed = {
    rotation = time_rotating.sp_password_rotation.id
  }
}

resource "azurerm_role_assignment" "automation_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azuread_service_principal.automation.object_id
}

# Credentials go into OUR OWN Key Vault (never printed to stdout/state
# output, never committed) -- scripts read them from there, not from a
# checked-in file.
resource "azurerm_key_vault_secret" "sp_client_id" {
  name         = "automation-sp-client-id"
  value        = azuread_application.automation.client_id
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_key_vault_access_policy.current_user]
}

resource "azurerm_key_vault_secret" "sp_client_secret" {
  name         = "automation-sp-client-secret"
  value        = azuread_service_principal_password.automation.value
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_key_vault_access_policy.current_user]
}

resource "azurerm_key_vault_secret" "sp_tenant_id" {
  name         = "automation-sp-tenant-id"
  value        = data.azurerm_client_config.current.tenant_id
  key_vault_id = azurerm_key_vault.main.id
  depends_on   = [azurerm_key_vault_access_policy.current_user]
}
