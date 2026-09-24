resource "azurerm_kubernetes_cluster" "main" {
  name                = "aks-${local.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = "article2ebpf"
  kubernetes_version  = null # let Azure pick the current default GA version

  default_node_pool {
    # Two real, empirically discovered dead ends before this: Standard_D4s_v5
    # (standardDSv5Family quota 0/0 in eastus2), then Standard_D4s_v6
    # (priced/listed, but `az vm list-skus` showed a
    # NotAvailableForSubscription zone restriction covering all 3 zones in
    # eastus2 for this specific subscription). Standard_D4s_v7 was verified
    # via a full `az vm list-skus` dump filtered to
    # `restrictions[0]==null` (genuinely zero restrictions, not just
    # "didn't check") AND `az vm list-usage` shows StandardDsv7Family at
    # 0/10 vCPUs -- 2 nodes x 4 vCPUs = 8, fits with margin. See
    # EXPERIMENTS_LOG.md Phase 8.
    name           = "system"
    node_count     = 2
    vm_size        = "Standard_D4s_v7"
    vnet_subnet_id = azurerm_subnet.aks.id
    tags           = local.tags
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "azure"
  }

  tags = local.tags
}

# Confidential H100 GPU node pool. Disabled by default (rule 5: GPU
# resources exist only during active measurement campaigns) -- created via
# `terraform apply -var enable_gpu_pool=true` for the duration of Phase 9,
# then torn back down (see deploy/azure/scripts/).
#
# SKU/region/quota verified with real `az cli` calls on 2026-08-01, not
# assumed: Standard_NCC40ads_H100_v5 (AMD SEV-SNP confidential VM + 1x H100,
# 40 vCPUs, 320GB RAM) is available in eastus2, and this subscription's
# StandardNCCads2023Family quota there is 40/40 vCPUs -- exactly one node,
# see EXPERIMENTS_LOG.md Phase 7.
resource "azurerm_kubernetes_cluster_node_pool" "gpu" {
  count = var.enable_gpu_pool ? 1 : 0

  name                  = "gpuh100"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.main.id
  vm_size               = "Standard_NCC40ads_H100_v5"
  node_count            = var.gpu_node_count
  vnet_subnet_id        = azurerm_subnet.aks.id

  # Real, empirically discovered: AKS's automatic GPU driver installation
  # does NOT support the confidential (NCC, double-C) H100 SKU -- the API
  # error explicitly listed standard_nc40ads_h100_v5 (single C,
  # non-confidential) as supported but rejected ours with
  # VMSizeDoesNotSupportGPU. `gpu_driver = "None"` skips AKS's own install
  # path; Phase 9 must install NVIDIA's confidential-computing-aware driver
  # itself (see EXPERIMENTS_LOG.md Phase 8) before any GPU-dependent
  # workload/preflight check can run.
  gpu_driver = "None"

  node_taints = ["sku=gpu-confidential:NoSchedule"]

  tags = local.tags
}

# Least-privilege ACR pull access for the AKS kubelet identity -- no admin
# credentials, no subscription-wide role.
resource "azurerm_role_assignment" "aks_acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_kubernetes_cluster.main.kubelet_identity[0].object_id
}
