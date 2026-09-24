output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.main.name
}

output "acr_login_server" {
  value = azurerm_container_registry.main.login_server
}

output "storage_account_name" {
  value = azurerm_storage_account.results.name
}

output "key_vault_name" {
  value = azurerm_key_vault.main.name
}

output "gpu_pool_enabled" {
  value = var.enable_gpu_pool
}

output "foundry_project_name" {
  value = azurerm_ai_foundry_project.main.name
}
