variable "project" {
  description = "Name prefix of every resource."
  type        = string
  default     = "iacgraph-demo"
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
}

variable "availability_zones" {
  description = "Two zones, so the database subnet group has two subnets (RDS requires it)."
  type        = list(string)
  default     = ["eu-central-1a", "eu-central-1b"]
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  type    = list(string)
  default = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "ec2_instance_type" {
  type    = string
  default = "t3.micro"
}

variable "db_instance_class" {
  type    = string
  default = "db.t3.micro"
}

variable "bucket_suffix" {
  description = "S3 bucket names are global: choose a random value of your own (e.g. openssl rand -hex 4)."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{4,20}$", var.bucket_suffix))
    error_message = "bucket_suffix: 4-20 characters, lower-case letters, digits and hyphens."
  }
}
