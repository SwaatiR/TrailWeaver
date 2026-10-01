output "api_repository_url" {
  description = "ECR repository URL for the TrailWeaver API image."
  value       = aws_ecr_repository.api.repository_url
}

output "dashboard_repository_url" {
  description = "ECR repository URL for the TrailWeaver dashboard image."
  value       = aws_ecr_repository.dashboard.repository_url
}

output "ecs_cluster_arn" {
  description = "ARN of the TrailWeaver ECS cluster."
  value       = aws_ecs_cluster.this.arn
}

output "cloudwatch_log_group_name" {
  description = "CloudWatch log group used by TrailWeaver containers."
  value       = aws_cloudwatch_log_group.runtime.name
}

output "execution_role_arn" {
  description = "ECS task execution role ARN."
  value       = aws_iam_role.execution.arn
}

output "task_role_arn" {
  description = "Workload role ARN with scoped CloudTrail S3 access."
  value       = aws_iam_role.task.arn
}

output "runtime_security_group_id" {
  description = "Security group ID for the future ECS task."
  value       = aws_security_group.runtime.id
}

output "efs_file_system_id" {
  description = "Encrypted EFS file system ID for SQLite persistence."
  value       = aws_efs_file_system.incidents.id
}

output "efs_access_point_id" {
  description = "EFS access point ID configured for the non-root API user."
  value       = aws_efs_access_point.incidents.id
}

output "application_url" {
  description = "HTTPS URL of the TrailWeaver load balancer; configure DNS separately for certificate hostname validation."
  value       = "https://${aws_lb.this.dns_name}"
}

output "ecs_service_name" {
  description = "Name of the single-instance TrailWeaver ECS service."
  value       = aws_ecs_service.this.name
}
