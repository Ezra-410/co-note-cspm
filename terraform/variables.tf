variable "region" {
  description = "Single region used by the Co-note lab environment"
  type        = string
  default     = "eu-west-1"
}

variable "admin_profile" {
  description = "AWS CLI profile used to create the environment (ezra-admin)"
  type        = string
  default     = "conote-admin"
}

variable "admin_user_name" {
  description = "IAM user allowed to assume the CSPM roles"
  type        = string
  default     = "ezra-admin"
}

variable "owner" {
  description = "Value of the Owner tag"
  type        = string
  default     = "ezra"
}

variable "alert_email" {
  description = "Email address subscribed to the CSPM SNS alert topic"
  type        = string
}

variable "github_repo" {
  description = "owner/repo allowed to run the scheduled CSPM workflow through OIDC"
  type        = string
  default     = "Ezra-410/co-note-cspm"
}

variable "enable_github_oidc" {
  description = "Create the GitHub OIDC provider + read-only role for scheduled scans"
  type        = bool
  default     = true
}

variable "instance_type" {
  description = "Co-note application host size (small to save credits)"
  type        = string
  default     = "t3.micro"
}
