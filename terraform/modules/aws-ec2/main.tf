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

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    environment = var.environment
  }))

  monitoring = true

  tags = {
    Name        = "${var.environment}-honeypot-${count.index + 1}"
    Environment = var.environment
    Role        = "honeypot"
  }
}

# IAM role for CloudWatch and S3 access
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
}

resource "aws_iam_role_policy_attachment" "cloudwatch_logs" {
  role       = aws_iam_role.honeypot.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent" {
  role       = aws_iam_role.honeypot.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "honeypot" {
  name_prefix = "${var.environment}-honeypot-"
  role        = aws_iam_role.honeypot.name
}

output "instance_ids" {
  value = aws_instance.honeypot[*].id
}

output "instance_ips" {
  value = aws_instance.honeypot[*].public_ip
}

output "ami_id" {
  value = data.aws_ami.ubuntu.id
}
