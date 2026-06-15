variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

variable "honeypot_subnet_cidr" {
  description = "Honeypot subnet CIDR"
  type        = string
  default     = "10.0.1.0/24"
}

variable "instance_type" {
  description = "EC2 instance type (t3.micro = free tier eligible)"
  type        = string
  default     = "t3.micro"
}

variable "honeypot_count" {
  description = "Number of honeypot instances to deploy"
  type        = number
  default     = 1
}

variable "key_pair_name" {
  description = "EC2 key pair for admin SSH access"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block for admin SSH access (set to your IP)"
  type        = string
  default     = "0.0.0.0/0" # Change to your IP for security
}

variable "log_retention_days" {
  description = "CloudWatch log retention period"
  type        = number
  default     = 30
}
