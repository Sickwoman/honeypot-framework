# AWS VPC Module - Network isolation for honeypots

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
}

variable "honeypot_subnet_cidr" {
  description = "Honeypot subnet CIDR"
  type        = string
}

resource "aws_vpc" "honeypot" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.environment}-vpc"
    Environment = var.environment
  }
}

resource "aws_subnet" "honeypot" {
  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = var.honeypot_subnet_cidr
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.environment}-honeypot-subnet"
    Environment = var.environment
  }
}

resource "aws_internet_gateway" "honeypot" {
  vpc_id = aws_vpc.honeypot.id

  tags = {
    Name        = "${var.environment}-igw"
    Environment = var.environment
  }
}

resource "aws_route_table" "honeypot" {
  vpc_id = aws_vpc.honeypot.id

  route {
    cidr_block      = "0.0.0.0/0"
    gateway_id      = aws_internet_gateway.honeypot.id
  }

  tags = {
    Name        = "${var.environment}-rt"
    Environment = var.environment
  }
}

resource "aws_route_table_association" "honeypot" {
  subnet_id      = aws_subnet.honeypot.id
  route_table_id = aws_route_table.honeypot.id
}

data "aws_availability_zones" "available" {
  state = "available"
}

output "vpc_id" {
  value = aws_vpc.honeypot.id
}

output "subnet_id" {
  value = aws_subnet.honeypot.id
}

output "internet_gateway_id" {
  value = aws_internet_gateway.honeypot.id
}
