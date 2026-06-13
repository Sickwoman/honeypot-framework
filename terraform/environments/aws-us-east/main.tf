terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  environment = "aws-us-east"
  region      = "us-east-1"
  region_name = "North America (US East)"
  
  common_tags = {
    Environment = local.environment
    Region      = local.region
    Project     = "honeypot-framework"
    ManagedBy   = "Terraform"
  }
}

output "aws_region" {
  description = "AWS region deployed to"
  value       = data.aws_region.current.name
}

output "aws_account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "deployment_summary" {
  description = "Phase 2 deployment summary"
  value = {
    environment = local.environment
    region      = local.region
    region_name = local.region_name
    status      = "Ready for deployment"
  }
}
