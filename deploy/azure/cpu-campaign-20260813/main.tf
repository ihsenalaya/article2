locals {
  tags = {
    project     = var.project
    purpose     = var.purpose
    owner       = var.owner
    environment = var.environment
    created-by  = var.created_by
    expires     = var.expires
  }
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${var.name_prefix}"
  location = var.location
  tags     = local.tags
}

resource "azurerm_virtual_network" "main" {
  name                = "vnet-${var.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = ["10.43.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "kubernetes" {
  name                 = "snet-kubernetes"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = ["10.43.1.0/24"]
}

resource "azurerm_network_security_group" "kubernetes" {
  name                = "nsg-${var.name_prefix}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  security_rule {
    name                       = "AllowSshFromResearchWorkstation"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowKubernetesApiFromResearchWorkstation"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "6443"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowNodeToNodeInsideVnet"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "VirtualNetwork"
    destination_address_prefix = "VirtualNetwork"
  }
}

resource "azurerm_subnet_network_security_group_association" "kubernetes" {
  subnet_id                 = azurerm_subnet.kubernetes.id
  network_security_group_id = azurerm_network_security_group.kubernetes.id
}

resource "azurerm_public_ip" "control_plane" {
  name                = "pip-${var.name_prefix}-cp"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_public_ip" "worker" {
  name                = "pip-${var.name_prefix}-worker"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "control_plane" {
  name                = "nic-${var.name_prefix}-cp"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.kubernetes.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.43.1.10"
    public_ip_address_id          = azurerm_public_ip.control_plane.id
  }
}

resource "azurerm_network_interface" "worker" {
  name                = "nic-${var.name_prefix}-worker"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.kubernetes.id
    private_ip_address_allocation = "Static"
    private_ip_address            = "10.43.1.20"
    public_ip_address_id          = azurerm_public_ip.worker.id
  }
}

resource "azurerm_linux_virtual_machine" "control_plane" {
  name                            = "vm-${var.name_prefix}-cp"
  location                        = azurerm_resource_group.main.location
  resource_group_name             = azurerm_resource_group.main.name
  size                            = var.control_plane_vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.control_plane.id]
  custom_data                     = base64encode(templatefile("${path.module}/cloud-init/node.yaml.tftpl", { role = "control-plane" }))
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  os_disk {
    name                 = "osdisk-${var.name_prefix}-cp"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

resource "azurerm_linux_virtual_machine" "worker" {
  name                            = "vm-${var.name_prefix}-worker"
  location                        = azurerm_resource_group.main.location
  resource_group_name             = azurerm_resource_group.main.name
  size                            = var.worker_vm_size
  admin_username                  = var.admin_username
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.worker.id]
  custom_data                     = base64encode(templatefile("${path.module}/cloud-init/node.yaml.tftpl", { role = "worker" }))
  tags                            = local.tags

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.ssh_public_key
  }

  os_disk {
    name                 = "osdisk-${var.name_prefix}-worker"
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}

# Cost-protection backstop (experiment protocol rule 14): auto-shutdown both VMs
# daily even if a work session forgets to run the teardown script.
resource "azurerm_dev_test_global_vm_shutdown_schedule" "control_plane" {
  virtual_machine_id   = azurerm_linux_virtual_machine.control_plane.id
  location              = azurerm_resource_group.main.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "worker" {
  virtual_machine_id   = azurerm_linux_virtual_machine.worker.id
  location              = azurerm_resource_group.main.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}
