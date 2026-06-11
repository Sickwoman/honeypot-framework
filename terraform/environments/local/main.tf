# ─────────────────────────────────────────
# Honeypot Module
# Reusable across local, AWS, and other envs
# ─────────────────────────────────────────

variable "honeypot_name" {
  type    = string
  default = "honeypot-01"
}

variable "environment" {
  type    = string
  default = "local"
}

variable "services" {
  type    = list(string)
  default = ["ssh", "http", "ftp"]
}

variable "region" {
  type    = string
  default = "local"
}

output "honeypot_config" {
  value = {
    name        = var.honeypot_name
    environment = var.environment
    services    = var.services
    region      = var.region
  }
}
