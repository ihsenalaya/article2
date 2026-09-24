output "resource_group_name" {
  value = azurerm_resource_group.main.name
}

output "location" {
  value = azurerm_resource_group.main.location
}

output "control_plane_public_ip" {
  value = azurerm_public_ip.control_plane.ip_address
}

output "control_plane_private_ip" {
  value = azurerm_network_interface.control_plane.private_ip_address
}

output "worker_public_ip" {
  value = azurerm_public_ip.worker.ip_address
}

output "worker_private_ip" {
  value = azurerm_network_interface.worker.private_ip_address
}

output "admin_username" {
  value = var.admin_username
}

output "control_plane_vm_size" {
  value = var.control_plane_vm_size
}

output "worker_vm_size" {
  value = var.worker_vm_size
}
