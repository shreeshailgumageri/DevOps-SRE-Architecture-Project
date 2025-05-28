# Terraform module for creating IAM roles

resource "aws_iam_role" "example" {
  name = var.role_name
  assume_role_policy = data.aws_iam_policy_document.assume_role_policy.json
}