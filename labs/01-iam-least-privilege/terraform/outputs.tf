output "reports_bucket" {
  description = "Name of the test bucket the analyst may read."
  value       = aws_s3_bucket.data.bucket
}

output "analyst_user" {
  description = "IAM user to test with. Set a console password and MFA device manually."
  value       = aws_iam_user.analyst.name
}

output "boundary_policy_arn" {
  description = "ARN of the permission boundary capping the analyst."
  value       = aws_iam_policy.boundary.arn
}
