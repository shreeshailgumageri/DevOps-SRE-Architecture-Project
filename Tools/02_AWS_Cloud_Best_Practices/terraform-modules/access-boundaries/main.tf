# Terraform module for access boundary policies

resource "aws_iam_policy" "access_boundary" {
  name   = var.policy_name
  policy = data.aws_iam_policy_document.access_boundary.json
}