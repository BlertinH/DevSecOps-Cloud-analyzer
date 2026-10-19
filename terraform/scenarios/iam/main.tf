# Scenario "iam": IAM policies with wildcards, and what the tool cannot see.
#   app_s3       -> "s3:*" on every bucket (plus a Deny on "secrets")       => CFG-02 (medium)
#   admin_all    -> "*" on "*" (full administrator), attached to role admin => CFG-02 (medium)
#   *_assume_admin -> only sts:AssumeRole on one named role                 => no finding
#   ci_logs      -> s3:PutObject on one bucket (ARN known only after apply) => warning, not checked
#   report_read  -> s3:GetObject on one bucket path (from a data source)    => no finding
#   app_readonly -> AWS-managed ReadOnlyAccess, not part of the plan        => warning
# The server "app" has no firewall rule open to the Internet, so there is no attack path
# and both findings stay medium: below fail_on "high", the gate passes.
# Limitation shown here: the Deny on "secrets" is not evaluated, so the edge app -> secrets
# is still drawn (the tool may report too much access, never too little).
# Expected: 2 findings, gate PASS.

variable "ami" {
  type    = string
  default = "ami-0abcdef1234567890"
}

variable "account_id" {
  type    = string
  default = "111122223333"
}

resource "aws_s3_bucket" "reports" {
  bucket = "iacgraph-probe-reports"
}

resource "aws_s3_bucket" "secrets" {
  bucket = "iacgraph-probe-secrets"
}

resource "aws_s3_bucket" "logs" {
  bucket = "iacgraph-probe-logs"
}

resource "aws_iam_role" "app" {
  name = "iacgraph-probe-app"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "iacgraph-probe-app"
  role = aws_iam_role.app.name
}

resource "aws_instance" "app" {
  ami                  = var.ami
  instance_type        = "t3.micro"
  iam_instance_profile = aws_iam_instance_profile.app.name
}

resource "aws_iam_role_policy" "app_s3" {
  name = "s3-all-but-secrets"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:*"
        Resource = "*"
      },
      {
        Effect = "Deny"
        Action = "s3:*"
        Resource = [
          "arn:aws:s3:::iacgraph-probe-secrets",
          "arn:aws:s3:::iacgraph-probe-secrets/*",
        ]
      },
    ]
  })
}

resource "aws_iam_role_policy" "app_assume_admin" {
  name = "assume-admin"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = "arn:aws:iam::${var.account_id}:role/iacgraph-probe-admin"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "app_readonly" {
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

resource "aws_iam_role" "admin" {
  name = "iacgraph-probe-admin"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:aws:iam::${var.account_id}:role/iacgraph-probe-app" }
    }]
  })
}

resource "aws_iam_policy" "admin_all" {
  name = "iacgraph-probe-admin-all"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_all" {
  role       = aws_iam_role.admin.name
  policy_arn = aws_iam_policy.admin_all.arn
}

resource "aws_iam_role" "ci" {
  name = "iacgraph-probe-ci"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "ci_assume_admin" {
  name = "assume-admin"
  role = aws_iam_role.ci.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "sts:AssumeRole"
      Resource = "arn:aws:iam::${var.account_id}:role/iacgraph-probe-admin"
    }]
  })
}

resource "aws_iam_role_policy" "ci_logs" {
  name = "write-logs"
  role = aws_iam_role.ci.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.logs.arn}/*"
    }]
  })
}

data "aws_iam_policy_document" "report_read" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["arn:aws:s3:::iacgraph-probe-reports/*"]
  }
}

resource "aws_iam_role" "report" {
  name = "iacgraph-probe-report"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "report_read" {
  name   = "read-reports"
  role   = aws_iam_role.report.id
  policy = data.aws_iam_policy_document.report_read.json
}
