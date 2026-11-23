#!/usr/bin/env bash
# =============================================================================
# Milestone 6 / Step 6 - CloudWatch alarm on a metric PUBLISHED BY CLOUD
# CUSTODIAN (-m aws). The namespace and dimensions are NOT assumed: they are
# read from `aws cloudwatch list-metrics` and reused exactly.
# Runs as the admin (the auditor may publish metrics but not create alarms).
# =============================================================================
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$HOME/co-note-cspm}"
export AWS_PROFILE=conote-admin AWS_REGION=eu-west-1
POLICY="${1:-detect-public-ssh-access}"
TOPIC=$(cd "$PROJECT_DIR/terraform" && terraform output -raw sns_topic_arn)

echo ">> Namespaces with Custodian metrics:"
aws cloudwatch list-metrics --query "Metrics[?Namespace=='CloudMaid'].[Namespace,MetricName]" --output text | sort -u

DIMS=$(aws cloudwatch list-metrics --namespace CloudMaid --metric-name ResourceCount \
  --dimensions Name=Policy,Value="$POLICY" --query "Metrics[0].Dimensions" --output json)
[ "$DIMS" != "null" ] || { echo "No ResourceCount metric for $POLICY yet - run scripts/custodian-scan.sh first"; exit 1; }
echo ">> Dimensions found for $POLICY: $DIMS"

aws cloudwatch put-metric-alarm \
  --alarm-name "CoNote-Custodian-${POLICY}" \
  --alarm-description "Cloud Custodian policy $POLICY matched at least one resource" \
  --namespace CloudMaid --metric-name ResourceCount \
  --dimensions "$DIMS" \
  --statistic Maximum --period 3600 --evaluation-periods 1 \
  --threshold 0 --comparison-operator GreaterThanThreshold \
  --treat-missing-data notBreaching \
  --alarm-actions "$TOPIC" --ok-actions "$TOPIC"
aws cloudwatch describe-alarms --alarm-names "CoNote-Custodian-${POLICY}" \
  --query "MetricAlarms[0].[AlarmName,Namespace,MetricName,StateValue]" --output table
