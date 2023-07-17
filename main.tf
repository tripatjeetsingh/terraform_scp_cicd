terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.2.0"
    }
  }
  backend "s3" {
    bucket = "scp-cicd-terraform-remote-backend"
    key    = "scp-tf-state-file"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-2" # define region as per your account
}

#resource "aws_s3_bucket" "new_bucket" {
#  bucket = "demo-github-action-tf-04203023"
#
#  object_lock_enabled = false
#
#  tags = {
#    Environment = "qa"
#  }
#}
#resource "aws_instance" "server" {
#  ami           = "ami-08333bccc35d71140"
#  instance_type = "t2.micro"
#}

## Deploy S3 AWS Org SCPs
module "s3" {
  source = "./modules/s3"

  #target_id       = var.target_id
  #region_lockdown = var.region_lockdown
}
