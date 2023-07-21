terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=4.2.0"
    }
  }
  # Configure the remote s3 bucket backend to store the terraform state file
  backend "s3" {
    bucket = "scp-cicd-terraform-remote-backend"
    key    = "scp-tf-state-file"
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "us-east-2" # define region as per your account
}

# Deploy Security Control AWS Org SCPs for UMB
module "security_controls_scp" {
  source = "./security_controls_scp"

  target_id       = var.target_id
  region_lockdown = var.region_lockdown
}

