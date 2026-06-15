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

# VPC Module
module "vpc" {
  source = "../../modules/aws-vpc"
  
  environment           = local.environment
  region                = local.region
  vpc_cidr              = var.vpc_cidr
  honeypot_subnet_cidr  = var.honeypot_subnet_cidr
}

# Security Group Module
module "security_group" {
  source = "../../modules/aws-security-group"
  
  environment         = local.environment
  vpc_id              = module.vpc.vpc_id
  allowed_ssh_cidr    = var.allowed_ssh_cidr
}

# CloudWatch Module
module "cloudwatch" {
  source = "../../modules/aws-cloudwatch"
  
  environment          = local.environment
  log_retention_days   = var.log_retention_days
}

# S3 Module
module "s3" {
  source = "../../modules/aws-s3"
  
  environment          = local.environment
  region               = local.region
  log_retention_days   = var.log_retention_days
}

# EC2 Module - Honeypot Instances
# PREREQUISITES BEFORE UNCOMMENTING:
#   1. Run: aws ec2 create-key-pair --key-name honeypot-framework-us-east --query 'KeyMaterial' --output text > honeypot-key.pem
#   2. Set permissions: chmod 400 honeypot-key.pem
#   3. Set var.key_pair_name in terraform.tfvars to "honeypot-framework-us-east"
#   4. Configure AWS credentials: aws configure
#   5. Uncomment the module below
#   6. Run: terraform plan to verify
#   7. Run: terraform apply to deploy

module "ec2" {
  source = "../../modules/aws-ec2"
  
  environment       = local.environment
  instance_count    = var.honeypot_count
  instance_type     = var.instance_type
  subnet_id         = module.vpc.subnet_id
  security_group_id = module.security_group.security_group_id
  key_pair_name     = var.key_pair_name
}

# Outputs
output "aws_region" {
  description = "AWS region"
  value       = data.aws_region.current.name
}

output "aws_account_id" {
  description = "AWS account ID"
  value       = data.aws_caller_identity.current.account_id
}

output "vpc_id" {
  description = "VPC ID"
  value       = module.vpc.vpc_id
}

output "security_group_id" {
  description = "Security group ID"
  value       = module.security_group.security_group_id
}

output "honeypot_instances" {
  description = "Honeypot instance details"
  value = {
    instance_ids = module.ec2.instance_ids
    instance_ips = module.ec2.instance_ips
  }
}

output "cloudwatch_logs" {
  description = "CloudWatch log groups"
  value = {
    cowrie    = module.cloudwatch.cowrie_log_group
    opencanary = module.cloudwatch.opencanary_log_group
    system    = module.cloudwatch.system_log_group
  }
}

output "s3_bucket" {
  description = "S3 bucket for logs"
  value       = module.s3.bucket_name
}

output "deployment_summary" {
  description = "Phase 2 deployment summary"
  value = {
    environment = local.environment
    region      = local.region
    region_name = local.region_name
    status      = "Ready for deployment"
    modules = {
      vpc              = "✅ Created"
      security_group   = "✅ Created"
      cloudwatch       = "✅ Created"
      s3               = "✅ Created"
      ec2              = "✅ Ready (uncommented)"
    }
  }
}
