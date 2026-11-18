#!/usr/bin/env bash
# =============================================================================
# Hourly Cloud Custodian evaluation (Milestone 3 + 6) - DETECTION policies only.
#   -m aws  -> Custodian publishes its own metrics (namespace CloudMaid)
#   output  -> reports/custodian/<UTC date>/<policy>/resources.json
# =============================================================================
source "$(dirname "$0")/common.sh"
OUTPUT_DIR="$REPORTS/custodian/$NOW"
mkdir -p "$OUTPUT_DIR"
source "$CUSTODIAN_ENV/bin/activate"

custodian run -s "$OUTPUT_DIR" -m aws --region "$REGION" \
  "$PROJECT_DIR/cloud-custodian/policies/security-baseline.yml" \
  "$PROJECT_DIR"/cloud-custodian/policies/aws/*.yml

echo "Violations per policy:"
for d in "$OUTPUT_DIR"/*/; do
  p=$(basename "$d"); n=$(jq length "$d/resources.json" 2>/dev/null || echo "?")
  printf "  %-45s %s\n" "$p" "$n"
done
put_metric ScanCompleted 1
echo "Cloud Custodian assessment completed: $OUTPUT_DIR"
