# Terraform module for audit logging configurations

resource "aws_cloudwatch_log_group" "audit" {
  name = "/iam/audit"
  retention_in_days = 90
}