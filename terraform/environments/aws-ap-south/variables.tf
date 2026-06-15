variable "vpc_cidr" {
  type    = string
  default = "10.2.0.0/16"
}

variable "honeypot_subnet_cidr" {
  type    = string
  default = "10.2.1.0/24"
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "honeypot_count" {
  type    = number
  default = 1
}

variable "key_pair_name" {
  type = string
}

variable "allowed_ssh_cidr" {
  type    = string
  default = "0.0.0.0/0"
}

variable "log_retention_days" {
  type    = number
  default = 30
}
