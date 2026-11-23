#!/usr/bin/env bash
# =============================================================================
# Daily Prowler security assessment (Milestone 2 + 6)
#   reports/prowler/<UTC date>/  json-ocsf + html + csv (+ compliance/ folder)
#   data/prowler_findings.csv    normalised latest results (dashboard)
#   data/scan_history.csv        one line per scan (trend)
#   CloudWatch CoNote/CSPM       CriticalFindings, HighFindings, FailedChecks,
#                                ScanCompleted (alarm + heartbeat)
# Usage: prowler-scan.sh [extra prowler args, e.g. --compliance cis_5.0_aws]
# =============================================================================
source "$(dirname "$0")/common.sh"
REPORT_DIR="$REPORTS/prowler/$NOW"
mkdir -p "$REPORT_DIR"

echo "[$(date -u +%FT%TZ)] Starting Co-note CSPM assessment (profile $AWS_PROFILE, region $REGION)..."
source "$PROWLER_ENV/bin/activate"

# Prowler exit code 3 = "scan finished and found FAIL findings" -> not an error.
set +e
prowler aws --region "$REGION" \
  --output-formats json-ocsf html csv \
  --output-directory "$REPORT_DIR" \
  --mutelist-file "$PROJECT_DIR/prowler/mutelist.yaml" \
  --no-banner "$@"
rc=$?
set -e
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  echo "Prowler failed (exit $rc) - no metrics published, heartbeat alarm will fire."
  exit "$rc"
fi

KIND=full
case " $* " in *" --compliance "*) KIND=compliance ;; esac
summary="$(python3 "$PROJECT_DIR/scripts/prowler_to_csv.py" "$REPORT_DIR" "$DATA_DIR" "$KIND")"
echo "Summary: $summary"
crit=$(echo "$summary" | jq -r .critical)
high=$(echo "$summary" | jq -r .high)
fail=$(echo "$summary" | jq -r .fail)

# Severity metrics come from FULL scans only (a compliance run checks a subset
# and would make the numbers jump down and up).
if [ "$KIND" = full ]; then
  put_metric CriticalFindings "$crit"
  put_metric HighFindings "$high"
  put_metric FailedChecks "$fail"
fi
put_metric ScanCompleted 1

echo "Assessment completed. Critical=$crit High=$high Failed=$fail"
echo "Reports stored in: $REPORT_DIR"
