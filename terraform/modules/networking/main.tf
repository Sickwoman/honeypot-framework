# ─────────────────────────────────────────
# Networking Module
# Defines isolated network for honeypots
# ─────────────────────────────────────────

variable "network_cidr" {
  type    = string
  default = "192.168.56.0/24"
}

variable "environment" {
  type    = string
  default = "local"
}

variable "allow_inbound_ports" {
  description = "Ports open to attackers (honeypot bait)"
  type        = list(number)
  default     = [22, 23, 80, 443, 21, 3306, 5432]
}

variable "management_cidr" {
  description = "Your trusted IP range for admin access"
  type        = string
  default     = "127.0.0.1/32"
}

output "network_config" {
  value = {
    cidr              = var.network_cidr
    environment       = var.environment
    open_ports        = var.allow_inbound_ports
    management_access = var.management_cidr
  }
}
