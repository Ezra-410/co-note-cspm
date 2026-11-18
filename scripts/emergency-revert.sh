#!/usr/bin/env bash
# Safety net ONLY (e.g. you must stop for the day before finishing the
# challenge). The graded path is the Cloud Custodian controlled remediation.
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/co-note-cspm}"
export AWS_PROFILE=conote-admin
cd "$PROJECT_DIR/terraform"
SG=$(terraform output -raw admin_security_group_id)
BUCKET=$(terraform output -raw uploads_bucket)
aws ec2 revoke-security-group-ingress --group-id "$SG" --protocol tcp --port 22 --cidr 0.0.0.0/0 || true
aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
terraform apply -auto-approve -target='aws_s3_bucket_policy.all["uploads"]'
echo "Reverted."
