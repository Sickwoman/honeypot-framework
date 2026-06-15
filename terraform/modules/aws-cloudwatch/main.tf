# AWS CloudWatch Module - Centralized logging

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 30
}

# CloudWatch Log Groups for honeypots
resource "aws_cloudwatch_log_group" "cowrie" {
  name              = "/aws/honeypot/${var.environment}/cowrie"
  retention_in_days = var.log_retention_days

  tags = {
    Environment = var.environment
    Service     = "cowrie"
  }
}

resource "aws_cloudwatch_log_group" "opencanary" {
  name              = "/aws/honeypot/${var.environment}/opencanary"
  retention_in_days = var.log_retention_days

  tags = {
    Environment = var.environment
    Service     = "opencanary"
  }
}

resource "aws_cloudwatch_log_group" "system" {
  name              = "/aws/honeypot/${var.environment}/system"
  retention_in_days = var.log_retention_days

  tags = {
    Environment = var.environment
    Service     = "system"
  }
}

# CloudWatch Alarms for attack detection
resource "aws_cloudwatch_metric_alarm" "high_login_attempts" {
  alarm_name          = "${var.environment}-high-login-attempts"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "LoginAttempts"
  namespace           = "Honeypot"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  alarm_description   = "Alert when login attempts exceed 100 in 5 minutes"
  treat_missing_data  = "notBreaching"
}

resource "aws_cloudwatch_metric_alarm" "port_scan_detected" {
  alarm_name          = "${var.environment}-port-scan-detected"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "PortScanDetections"
  namespace           = "Honeypot"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alert on any port scan detection"
  treat_missing_data  = "notBreaching"
}

output "cowrie_log_group" {
  value = aws_cloudwatch_log_group.cowrie.name
}

output "opencanary_log_group" {
  value = aws_cloudwatch_log_group.opencanary.name
}

output "system_log_group" {
  value = aws_cloudwatch_log_group.system.name
}
