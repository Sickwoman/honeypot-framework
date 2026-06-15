# AWS EC2 Module - Honeypot instances

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "instance_count" {
  description = "Number of honeypot instances"
  type        = number
  default     = 1
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "subnet_id" {
  description = "Subnet ID for instances"
  type        = string
}

variable "security_group_id" {
  description = "Security group ID"
  type        = string
}

variable "key_pair_name" {
  description = "EC2 Key pair for admin SSH"
  type        = string
}

# Ubuntu 22.04 LTS AMI (x86_64)
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "honeypot" {
  count                = var.instance_count
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type
  subnet_id            = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  key_name             = var.key_pair_name
  
  # CloudWatch agent for logging
  iam_instance_profile = aws_iam_instance_profile.honeypot.name

  user_data = base64encode(file("${path.module}/user_data.sh"))

  monitoring = true

  tags = {
    Name        = "${var.environment}-honeypot-${count.index + 1}"
    Environment = var.environment
    Role        = "honeypot"
  }

  depends_on = [aws_iam_role_policy.honeypot_logs]
}

# IAM role for honeypot instance
resource "aws_iam_role" "honeypot" {
  name_prefix = "${var.environment}-honeypot-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Environment = var.environment
  }
}

# Least-privilege policy for CloudWatch Logs
resource "aws_iam_role_policy" "honeypot_logs" {
  name_prefix = "${var.environment}-honeypot-logs-"
  role        = aws_iam_role.honeypot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "CreateLogGroupAndStream"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:/aws/honeypot/*"
      },
      {
        Sid    = "DescribeLogGroups"
        Effect = "Allow"
        Action = [
          "logs:DescribeLogGroups"
        ]
        Resource = "arn:aws:logs:*:*:log-group:/aws/honeypot/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "honeypot" {
  name_prefix = "${var.environment}-honeypot-"
  role        = aws_iam_role.honeypot.name
}

output "instance_ids" {
  value       = aws_instance.honeypot[*].id
  description = "IDs of honeypot instances"
}

output "instance_ips" {
  value       = aws_instance.honeypot[*].public_ip
  description = "Public IPs of honeypot instances"
}

output "ami_id" {
  value       = data.aws_ami.ubuntu.id
  description = "AMI ID used for instances"
}
