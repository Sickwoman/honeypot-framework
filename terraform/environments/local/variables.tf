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

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "local"
}

variable "lab_name" {
  description = "Lab identifier"
  type        = string
  default     = "honeypot-local-lab"
}

variable "honeypot_hostname" {
  description = "Honeypot VM hostname"
  type        = string
  default     = "webserver01"
}

variable "honeypot_ip" {
  description = "Honeypot VM IP address"
  type        = string
  default     = "192.168.56.101"
}

variable "honeypot_ssh_port" {
  description = "Cowrie SSH honeypot port"
  type        = number
  default     = 2222
}

variable "opencanary_ftp_port" {
  description = "OpenCanary FTP port"
  type        = number
  default     = 21
}

variable "opencanary_http_port" {
  description = "OpenCanary HTTP port"
  type        = number
  default     = 80
}

variable "opencanary_mysql_port" {
  description = "OpenCanary MySQL port"
  type        = number
  default     = 3306
}

variable "opencanary_ssh_port" {
  description = "OpenCanary SSH port"
  type        = number
  default     = 2223
}

variable "opencanary_telnet_port" {
  description = "OpenCanary Telnet port"
  type        = number
  default     = 23
}

variable "log_path" {
  description = "OpenCanary log file path"
  type        = string
  default     = "/var/tmp/opencanary.log"
}

variable "cowrie_log_path" {
  description = "Cowrie log directory path"
  type        = string
  default     = "/home/cowrie/cowrie/var/log/cowrie"
}
