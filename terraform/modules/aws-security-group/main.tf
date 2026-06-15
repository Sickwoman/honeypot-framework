# AWS Security Group Module - Firewall rules for honeypots

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR for SSH admin access (your IP)"
  type        = string
  default     = "0.0.0.0/0" # Change this to your IP for production
}

resource "aws_security_group" "honeypot" {
  name_prefix = "${var.environment}-honeypot-"
  description = "Security group for honeypot instances"
  vpc_id      = var.vpc_id

  tags = {
    Name        = "${var.environment}-honeypot-sg"
    Environment = var.environment
  }
}

# Inbound: Honeypot bait ports (open to world)
resource "aws_vpc_security_group_ingress_rule" "cowrie_ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Cowrie SSH honeypot"
  from_port         = 2222
  to_port           = 2222
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "ftp" {
  security_group_id = aws_security_group.honeypot.id
  description       = "FTP bait"
  from_port         = 21
  to_port           = 21
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "http" {
  security_group_id = aws_security_group.honeypot.id
  description       = "HTTP bait"
  from_port         = 80
  to_port           = 80
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "mysql" {
  security_group_id = aws_security_group.honeypot.id
  description       = "MySQL bait"
  from_port         = 3306
  to_port           = 3306
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "telnet" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Telnet bait"
  from_port         = 23
  to_port           = 23
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

# Inbound: Admin SSH (restricted)
resource "aws_vpc_security_group_ingress_rule" "admin_ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Admin SSH access"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
  cidr_ipv4         = var.allowed_ssh_cidr
}

# Outbound: Block all (honeypot isolation)
resource "aws_vpc_security_group_egress_rule" "deny_all" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Deny all outbound (isolation)"
  from_port         = -1
  to_port           = -1
  ip_protocol       = "-1"
  cidr_ipv4         = "127.0.0.1/32" # Deny effectively
}

# Allow outbound to CloudWatch (logs)
resource "aws_vpc_security_group_egress_rule" "cloudwatch" {
  security_group_id = aws_security_group.honeypot.id
  description       = "Allow CloudWatch logs"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "0.0.0.0/0"
}

output "security_group_id" {
  value = aws_security_group.honeypot.id
}
