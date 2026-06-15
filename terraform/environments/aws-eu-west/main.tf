terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" { region = "eu-west-1" }

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  environment = "aws-eu-west"
  region      = "eu-west-1"
}

module "vpc" {
  source = "../../modules/aws-vpc"
  environment = local.environment
  region = local.region
  vpc_cidr = var.vpc_cidr
  honeypot_subnet_cidr = var.honeypot_subnet_cidr
}

module "security_group" {
  source = "../../modules/aws-security-group"
  environment = local.environment
  vpc_id = module.vpc.vpc_id
  allowed_ssh_cidr = var.allowed_ssh_cidr
}

module "cloudwatch" {
  source = "../../modules/aws-cloudwatch"
  environment = local.environment
  log_retention_days = var.log_retention_days
}

module "s3" {
  source = "../../modules/aws-s3"
  environment = local.environment
  region = local.region
  log_retention_days = var.log_retention_days
}

output "aws_account_id" { value = data.aws_caller_identity.current.account_id }
output "vpc_id" { value = module.vpc.vpc_id }
output "security_group_id" { value = module.security_group.security_group_id }
