output "environment" {
  description = "Current environment"
  value       = var.environment
}

output "lab_name" {
  description = "Lab identifier"
  value       = var.lab_name
}

output "honeypot_info" {
  description = "Honeypot VM details"
  value = {
    hostname     = var.honeypot_hostname
    ip           = var.honeypot_ip
    network      = var.lab_network
    services     = var.honeypot_services
  }
}

output "cowrie_config" {
  description = "Cowrie honeypot configuration"
  value = {
    service      = "Cowrie SSH Honeypot"
    port         = var.honeypot_ssh_port
    hostname     = var.honeypot_hostname
    log_path     = var.cowrie_log_path
    status       = "Running on port ${var.honeypot_ssh_port}"
  }
}

output "opencanary_services" {
  description = "OpenCanary active services"
  value = {
    ftp    = "port ${var.opencanary_ftp_port}"
    http   = "port ${var.opencanary_http_port}"
    mysql  = "port ${var.opencanary_mysql_port}"
    ssh    = "port ${var.opencanary_ssh_port}"
    telnet = "port ${var.opencanary_telnet_port}"
  }
}

output "logging_config" {
  description = "Logging configuration"
  value = {
    opencanary_log_path = var.log_path
    cowrie_log_path     = var.cowrie_log_path
    retention_days      = var.log_retention_days
    aggregation_status  = "Ready for ELK Stack integration"
  }
}

output "network_summary" {
  description = "Network isolation summary"
  value = {
    network_range      = var.lab_network
    honeypot_ip        = var.honeypot_ip
    isolation          = "Host-only (no internet access)"
    all_ports_summary  = "Cowrie:${var.honeypot_ssh_port}, FTP:${var.opencanary_ftp_port}, HTTP:${var.opencanary_http_port}, MySQL:${var.opencanary_mysql_port}, SSH:${var.opencanary_ssh_port}, Telnet:${var.opencanary_telnet_port}"
  }
}
