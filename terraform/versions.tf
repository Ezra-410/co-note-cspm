# =============================================================================
# Co-note CSPM lab environment - provider and version pinning
# State is kept LOCALLY (terraform.tfstate, git-ignored): this is a single-person
# lab account. In a team, use a remote backend (S3 + locking) instead.
# =============================================================================
terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.admin_profile

  # Every resource gets these tags -> Steampipe/Custodian can find "resources
  # without required tags" and group the inventory by environment.
  default_tags {
    tags = {
      Project     = "co-note"
      Environment = "lab"
      Owner       = var.owner
      ManagedBy   = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
