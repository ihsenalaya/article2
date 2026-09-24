# Budget alert (rule 5). This only sends email at 50/80/100% thresholds --
# it does NOT stop spend by itself. The actual spend-limiting mechanism is
# deploy/azure/scripts/safety-timeout.sh, run alongside any GPU-active
# measurement window.

resource "azurerm_monitor_action_group" "budget" {
  name                = "ag-${local.name_prefix}-budget"
  resource_group_name = azurerm_resource_group.main.name
  short_name          = "a2ebpfbud"

  email_receiver {
    name          = "owner"
    email_address = var.alert_email
  }
}

resource "azurerm_consumption_budget_resource_group" "main" {
  name              = "budget-${local.name_prefix}"
  resource_group_id = azurerm_resource_group.main.id

  amount     = var.budget_amount_usd
  time_grain = "Monthly"

  time_period {
    start_date = formatdate("YYYY-MM-01'T'00:00:00Z", timestamp())
  }

  notification {
    enabled        = true
    threshold      = 50
    operator       = "GreaterThanOrEqualTo"
    contact_emails = [var.alert_email]
  }

  notification {
    enabled        = true
    threshold      = 80
    operator       = "GreaterThanOrEqualTo"
    contact_emails = [var.alert_email]
  }

  notification {
    enabled        = true
    threshold      = 100
    operator       = "GreaterThanOrEqualTo"
    contact_emails = [var.alert_email]
  }

  lifecycle {
    ignore_changes = [time_period["start_date"]]
  }
}
