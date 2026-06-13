variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

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
  description = "EC2 instance type for honeypots"
  type        = string
  default     = "t3.micro"
}

variable "honeypot_count" {
  description = "Number of honeypot instances to deploy"
  type        = number
  default     = 1
}

variable "enable_detailed_monitoring" {
  description = "Enable detailed CloudWatch monitoring"
  type        = bool
  default     = true
}
