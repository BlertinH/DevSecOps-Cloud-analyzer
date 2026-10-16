resource "aws_s3_bucket" "data" {
  bucket        = "${var.project}-${var.bucket_suffix}-data"
  force_destroy = true

  tags = {
    Name      = "${var.project}-data"
    DataClass = "sensitive"
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
