# These three values go into the GitHub repository variables (step 14, part 6).

output "TF_STATE_BUCKET" {
  value = aws_s3_bucket.state.bucket
}

output "AWS_PLAN_ROLE_ARN" {
  value = aws_iam_role.plan.arn
}

output "AWS_DEPLOY_ROLE_ARN" {
  value = aws_iam_role.deploy.arn
}
