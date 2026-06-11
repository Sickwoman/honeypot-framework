# ─────────────────────────────────────────
# Logging Module
# Centralizes honeypot event collection
# ─────────────────────────────────────────

variable "log_destination" {
  description = "Where logs are shipped (local path or S3 bucket)"
  type        = string
  default     = "/var/log/honeypot"
}

variable "retention_days" {
  type    = number
  default = 30
}

variable "environment" {
  type    = string
  default = "local"
}

variable "log_types" {
  description = "Types of events to capture"
  type        = list(string)
  default     = [
    "ssh_attempts",
    "http_requests",
    "ftp_connections",
    "port_scans",
    "payload_captures"
  ]
}

output "logging_config" {
  value = {
    destination    = var.log_destination
    retention_days = var.retention_days
    log_types      = var.log_types
    environment    = var.environment
  }
}
