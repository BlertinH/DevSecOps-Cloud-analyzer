variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "github_subject" {
  description = "Start of the OIDC subject of the repository: repo:OWNER@OWNER_ID/REPO@REPO_ID"
  type        = string
  default     = "repo:BlertinH@185179106/DevSecOps-Cloud-analyzer@1421224980"
}

variable "bucket_suffix" {
  description = "S3 bucket names are global: a random value of your own (openssl rand -hex 4)."
  type        = string
}

variable "budget_email" {
  description = "Where the budget alerts are sent."
  type        = string
}

variable "budget_limit_usd" {
  type    = number
  default = 10
}
