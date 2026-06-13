output "vpc_id" {
  description = "VPC ID for honeypots"
  value       = "Pending — EC2 module"
}

output "honeypot_security_group_id" {
  description = "Security group for honeypots"
  value       = "Pending — Security group module"
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for honeypot logs"
  value       = "Pending — Logging module"
}

output "s3_bucket_logs" {
  description = "S3 bucket for long-term log storage"
  value       = "Pending — S3 module"
}
