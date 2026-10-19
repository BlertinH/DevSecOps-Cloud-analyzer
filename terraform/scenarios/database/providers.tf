# Evaluation scenarios are only planned, never applied. The fake credentials and
# the skip_* settings let `terraform plan` run without any AWS account or cost.
provider "aws" {
  region                      = "eu-central-1"
  access_key                  = "mock_access_key"
  secret_key                  = "mock_secret_key"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  skip_region_validation      = true
}
