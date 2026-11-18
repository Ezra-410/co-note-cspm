#!/usr/bin/env bash
# =============================================================================
# TEST ENVIRONMENT ONLY - simulate configuration DRIFT made "by hand",
# outside Terraform and outside the Lab 02 pipeline (final challenge).
#   ssh     : opens 22/tcp from 0.0.0.0/0 on conote-admin-sg
#   s3      : switches OFF the 4 public access block settings of the uploads
#             bucket and adds a public-read statement on share/* only,
#             with a harmless text file
# Runs as ezra-admin (a human administrator making a mistake).
# Usage: simulate-drift.sh ssh|s3|all
# =============================================================================
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/co-note-cspm}"
export AWS_PROFILE=conote-admin
cd "$PROJECT_DIR/terraform"
SG=$(terraform output -raw admin_security_group_id)
BUCKET=$(terraform output -raw uploads_bucket)
what="${1:-all}"

if [[ "$what" == ssh || "$what" == all ]]; then
  echo ">> Opening SSH to the world on $SG"
  aws ec2 authorize-security-group-ingress --group-id "$SG" \
    --ip-permissions 'IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=0.0.0.0/0,Description="temporary debug - drift test"}]'
fi

if [[ "$what" == s3 || "$what" == all ]]; then
  echo ">> Disabling public access block on $BUCKET"
  aws s3api put-public-access-block --bucket "$BUCKET" --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
  echo "Co-note public share test file - no sensitive content" > /tmp/conote-share.txt
  aws s3 cp /tmp/conote-share.txt "s3://$BUCKET/share/readme.txt"
  current=$(aws s3api get-bucket-policy --bucket "$BUCKET" --query Policy --output text)
  echo "$current" | jq --arg b "$BUCKET" '.Statement += [{
      "Sid":"PublicShareDrift","Effect":"Allow","Principal":"*",
      "Action":"s3:GetObject","Resource":("arn:aws:s3:::"+$b+"/share/*")}]' > /tmp/drift-policy.json
  aws s3api put-bucket-policy --bucket "$BUCKET" --policy file:///tmp/drift-policy.json
  echo ">> Public URL (should work now): https://$BUCKET.s3.amazonaws.com/share/readme.txt"
fi
echo "Drift injected at $(date -u +%FT%TZ) - record this time (detection-time metric)."
