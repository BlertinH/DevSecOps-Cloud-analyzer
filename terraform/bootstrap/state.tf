# The S3 bucket that keeps the Terraform state of the demos (used by the pipeline).

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "state" {
  bucket = "iacgraph-tfstate-${var.bucket_suffix}"

  lifecycle {
    prevent_destroy = true # the state must never be deleted by accident
  }
}

# Every change of the state is kept as a version, so an old state can be restored.
resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

# The state is encrypted at rest.
resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# The state is never public.
resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
