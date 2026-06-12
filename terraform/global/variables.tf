variable "project_name" {
  description = "Project name"
  type        = string
  default     = "honeypot-framework"
}

variable "organization" {
  description = "Organization/owner"
  type        = string
  default     = "security-team"
}

variable "tags" {
  description = "Common tags for all resources"
  type        = map(string)
  default = {
    Project = "honeypot-framework"
    ManagedBy = "Terraform"
    Purpose = "Threat intelligence and attack surface monitoring"
  }
}
