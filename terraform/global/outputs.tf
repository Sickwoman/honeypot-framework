output "project_name" {
  description = "Project identifier"
  value       = var.project_name
}

output "common_tags" {
  description = "Common tags applied to all resources"
  value       = var.tags
}

output "phases" {
  description = "Project phases and status"
  value = {
    phase_1_local_lab = "In Progress - Cowrie + OpenCanary operational"
    phase_2_aws_single_region = "Pending - Single region AWS deployment"
    phase_3_multi_region = "Pending - Multi-region AWS deployment"
    phase_4_threat_intel = "Pending - Threat intelligence enrichment"
    phase_5_multi_cloud = "Pending - Multi-cloud + auto-rotation"
  }
}
