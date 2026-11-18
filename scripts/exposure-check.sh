#!/usr/bin/env bash
# =============================================================================
# Every 15 minutes: critical PUBLIC EXPOSURE checks only (fast, cheap).
# Publishes CoNote/CSPM PublicExposure = number of exposed resources
#  -> alarm CoNote-CSPM-Public-Exposure -> SNS email.
# =============================================================================
source "$(dirname "$0")/common.sh"
OUT="$REPORTS/exposure/$NOW"
mkdir -p "$OUT"
source "$CUSTODIAN_ENV/bin/activate"

custodian run -s "$OUT" --region "$REGION" \
  "$PROJECT_DIR/cloud-custodian/policies/security-baseline.yml" >/dev/null 2>&1 || {
  echo "custodian run failed - see $OUT/*/custodian-run.log"; exit 1; }

count() { jq length "$OUT/$1/resources.json" 2>/dev/null || echo 0; }
ssh=$(count detect-public-ssh-access)
pab=$(count detect-public-s3-access-block-disabled)
ports=$(count detect-public-admin-ports)
pol=$(count detect-s3-public-policy)
total=$(( ssh + pab + ports + pol ))

put_metric PublicExposure "$total"
put_metric ScanCompleted 1

hist="$DATA_DIR/exposure_history.csv"
[ -f "$hist" ] || echo "scan_time,public_ssh,s3_block_incomplete,public_admin_ports,s3_public_policy,total" > "$hist"
echo "$(date -u +%FT%TZ),$ssh,$pab,$ports,$pol,$total" >> "$hist"
echo "[$(date -u +%FT%TZ)] public exposure: ssh=$ssh s3_block=$pab admin_ports=$ports s3_policy=$pol total=$total"
