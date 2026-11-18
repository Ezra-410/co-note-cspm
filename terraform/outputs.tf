output "account_id" {
  value = local.acct
}

output "region" {
  value = var.region
}

output "app_instance_id" {
  value = aws_instance.app.id
}

output "app_public_url" {
  value = "http://${aws_instance.app.public_ip}"
}

output "admin_security_group_id" {
  description = "Target of the public-SSH drift simulation"
  value       = aws_security_group.admin.id
}

output "uploads_bucket" {
  description = "Target of the public-bucket drift simulation"
  value       = aws_s3_bucket.this["uploads"].id
}

output "security_audit_role_arn" {
  value = aws_iam_role.security_audit.arn
}

output "remediator_role_arn" {
  value = aws_iam_role.remediator.arn
}

output "github_scan_role_arn" {
  value = var.enable_github_oidc ? aws_iam_role.github_scan[0].arn : ""
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
