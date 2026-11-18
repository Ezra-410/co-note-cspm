#!/usr/bin/env bash
# Shared settings for every CSPM script (sourced, not executed).
# shellcheck disable=SC2034  # variables are used by the scripts that source this file
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/co-note-cspm}"
REGION="${CSPM_REGION:-eu-west-1}"
# Scanners ALWAYS use the read-only role. In GitHub Actions the OIDC session
# credentials are already in the environment (CSPM_ENV_CREDS=1).
if [ "${CSPM_ENV_CREDS:-0}" = "1" ]; then unset AWS_PROFILE; else export AWS_PROFILE=conote-audit; fi
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"
DATA_DIR="$PROJECT_DIR/data"
REPORTS="$PROJECT_DIR/reports"
LOGS="$PROJECT_DIR/logs"
PROWLER_ENV="$PROJECT_DIR/prowler-env"
CUSTODIAN_ENV="$PROJECT_DIR/cloud-custodian/custodian-env"
NOW="$(date -u +%Y-%m-%d_%H-%M-%S)"
mkdir -p "$DATA_DIR" "$REPORTS" "$LOGS"

put_metric() {   # put_metric <name> <value>
  aws cloudwatch put-metric-data --namespace "CoNote/CSPM" \
    --metric-name "$1" --value "$2" --unit Count
}
