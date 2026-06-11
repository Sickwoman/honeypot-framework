variable "lab_network" {
  description = "VirtualBox host-only network range"
  type        = string
  default     = "192.168.56.0/24"
}

variable "honeypot_services" {
  description = "Simulated services on honeypot VM"
  type        = list(string)
  default     = ["ssh", "http", "ftp", "telnet"]
}

variable "log_retention_days" {
  description = "How many days to keep honeypot logs"
  type        = number
  default     = 30
}
