terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # The state lives in the S3 bucket of the bootstrap (step 14).
  # The bucket name is given at init: terraform init -backend-config="bucket=..."
  backend "s3" {
    key          = "demo-secure/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    use_lockfile = true
  }
}
