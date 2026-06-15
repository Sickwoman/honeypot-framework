# AWS S3 Module - Long-term log storage

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "region" {
  description = "AWS region"
  type        = string
}

variable "log_retention_days" {
  description = "Days before moving to Glacier"
  type        = number
  default     = 90
}

# S3 bucket for honeypot logs
resource "aws_s3_bucket" "honeypot_logs" {
  bucket_prefix = "${var.environment}-honeypot-logs-"

  tags = {
    Environment = var.environment
    Purpose     = "Honeypot log storage"
  }
}

# Block public access
resource "aws_s3_bucket_public_access_block" "honeypot_logs" {
  bucket = aws_s3_bucket.honeypot_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning
resource "aws_s3_bucket_versioning" "honeypot_logs" {
  bucket = aws_s3_bucket.honeypot_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy: Archive to Glacier after 90 days
resource "aws_s3_bucket_lifecycle_configuration" "honeypot_logs" {
  bucket = aws_s3_bucket.honeypot_logs.id

  rule {
    id     = "archive-to-glacier"
    status = "Enabled"

    transition {
      days          = var.log_retention_days
      storage_class = "GLACIER"
    }

    expiration {
      days = 365 # Delete after 1 year
    }
  }
}

# Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "honeypot_logs" {
  bucket = aws_s3_bucket.honeypot_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

output "bucket_name" {
  value = aws_s3_bucket.honeypot_logs.id
}

output "bucket_arn" {
  value = aws_s3_bucket.honeypot_logs.arn
}
