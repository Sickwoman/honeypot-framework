# OpenCanary Multi-Service Honeypot Configuration
# Replaces Dionaea (Python 3.13 incompatibility) with modern alternative

locals {
  opencanary_config = {
    service_name         = "OpenCanary Multi-Service Honeypot"
    version              = "0.9.8"
    installation_path    = "/usr/local/bin/opencanaryd"
    config_file          = "/etc/opencanaryd/opencanary.conf"
    log_file             = "/var/tmp/opencanary.log"
    
    active_services = {
      ftp = {
        port = 21
        captures = "login credentials, file upload attempts"
      }
      http = {
        port = 80
        captures = "HTTP requests, user-agents, paths"
      }
      mysql = {
        port = 3306
        captures = "connection attempts, query patterns"
      }
      ssh = {
        port = 2223
        captures = "login attempts, key exchanges"
      }
      telnet = {
        port = 23
        captures = "credentials, terminal commands"
      }
    }
    
    optional_services = {
      smb = {
        port = 445
        status = "disabled"
        note = "Enable for EternalBlue and ransomware detection"
      }
      rdp = {
        port = 3389
        status = "disabled"
        note = "Enable for remote desktop attacks"
      }
    }
  }
}

output "opencanary_configuration" {
  description = "OpenCanary deployment reference"
  value       = local.opencanary_config
}

output "opencanary_deployment_guide" {
  description = "OpenCanary setup commands"
  value = {
    install = "sudo pip3 install opencanary --break-system-packages"
    configure = "opencanaryd --copyconfig && sudo nano /etc/opencanaryd/opencanary.conf"
    start = "opencanaryd --start"
    status = "opencanaryd --status"
    logs = "tail -20 /var/tmp/opencanary.log"
  }
}
