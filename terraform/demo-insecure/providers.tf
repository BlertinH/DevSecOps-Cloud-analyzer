provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
      Purpose   = "iacgraph-thesis-demo"
    }
  }
}
