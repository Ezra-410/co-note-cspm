#!/usr/bin/env bash
# =============================================================================
# One-time: create the AWS CLI profiles for the CSPM roles (after terraform
# apply) and the Steampipe connection files.
#   conote-audit       -> assumes conote-security-audit   (read-only, scanners)
#   conote-remediator  -> assumes conote-cspm-remediator  (asks for MFA code)
# =============================================================================
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/co-note-cspm}"
cd "$PROJECT_DIR/terraform"
AUDIT=$(terraform output -raw security_audit_role_arn)
REMED=$(terraform output -raw remediator_role_arn)
REGION=$(terraform output -raw region)
MFA=$(AWS_PROFILE=conote-admin aws iam list-mfa-devices --query 'MFADevices[0].SerialNumber' --output text)
[ "$MFA" != "None" ] || { echo "ezra-admin has no MFA device - assign one first"; exit 1; }

aws configure set role_arn "$AUDIT" --profile conote-audit
aws configure set source_profile conote-admin --profile conote-audit
aws configure set region "$REGION" --profile conote-audit
aws configure set duration_seconds 3600 --profile conote-audit

aws configure set role_arn "$REMED" --profile conote-remediator
aws configure set source_profile conote-admin --profile conote-remediator
aws configure set mfa_serial "$MFA" --profile conote-remediator
aws configure set region "$REGION" --profile conote-remediator

mkdir -p ~/.steampipe/config
cat > ~/.steampipe/config/aws.spc <<SPC
connection "aws" {
  plugin  = "aws"
  profile = "conote-audit"
  regions = ["$REGION"]
}
SPC
cat > ~/.steampipe/config/csv.spc <<SPC
connection "csv" {
  plugin = "csv"
  paths  = ["$PROJECT_DIR/data/*.csv", "$PROJECT_DIR/registers/*.csv"]
}
SPC
echo "Profiles and Steampipe connections written."
echo "Test:  AWS_PROFILE=conote-audit aws sts get-caller-identity"
