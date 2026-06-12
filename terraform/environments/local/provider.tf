terraform {
  required_version = ">= 1.0"
  
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
  }
}

provider "null" {}

locals {
  description = "Local lab environment - VirtualBox honeypot setup"
  tags = {
    Environment = "local"
    Project     = "honeypot-framework"
    ManagedBy   = "Terraform"
    CreatedDate = timestamp()
  }
}
