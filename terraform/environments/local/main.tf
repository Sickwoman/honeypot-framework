locals {
  environment = var.environment
  lab_name    = var.lab_name

  honeypot_vm = {
    name     = "honeypot-01"
    ip       = var.honeypot_ip
    hostname = var.honeypot_hostname
    os       = "ubuntu-22.04"
    role     = "honeypot"
  }

  monitoring_vm = {
    name   = "monitor-01"
    ip     = "192.168.56.102"
    os     = "ubuntu-22.04"
    role   = "monitoring"
  }

  services = {
    cowrie = {
      name = "Cowrie SSH Honeypot"
      port = var.honeypot_ssh_port
      status = "running"
    }
    opencanary = {
      name = "OpenCanary Multi-Service"
      ports = [
        var.opencanary_ftp_port,
        var.opencanary_http_port,
        var.opencanary_mysql_port,
        var.opencanary_ssh_port,
        var.opencanary_telnet_port
      ]
      status = "running"
    }
  }
}

output "lab_summary" {
  description = "Local lab configuration summary"
  value = {
    environment = local.environment
    lab_name    = local.lab_name
    honeypot = {
      name     = local.honeypot_vm.name
      ip       = local.honeypot_vm.ip
      hostname = local.honeypot_vm.hostname
    }
    monitoring = {
      name = local.monitoring_vm.name
      ip   = local.monitoring_vm.ip
    }
    services = local.services
  }
}
