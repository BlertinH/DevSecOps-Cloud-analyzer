# Values printed after terraform apply (used later to test the real deployment).
output "web_public_ip" {
  value = aws_instance.web.public_ip
}

output "web_instance_id" {
  value = aws_instance.web.id
}

output "db_address" {
  value = aws_db_instance.main.address
}

output "bucket_name" {
  value = aws_s3_bucket.data.bucket
}

output "aws_region" {
  value = var.aws_region
}
