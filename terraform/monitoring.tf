# =============================================================================
# Monitoring and alerting (Milestone 6)
#
#  A. PERIODIC  : scans publish CoNote/CSPM metrics (CriticalFindings,
#                 PublicExposure) -> CloudWatch alarms -> SNS -> email
#  B. REAL-TIME : CloudTrail API events (security-group ingress opened, S3
#                 public-access block removed, bucket policy changed)
#                 -> EventBridge rule -> SNS -> email, within ~1-2 minutes
#
# The SNS topic is not KMS-encrypted on purpose: EventBridge and CloudWatch
# cannot publish to a topic encrypted with the AWS-managed SNS key. Accepted
# lab exception EXC-L02 (alert content contains no secrets).
# =============================================================================
resource "aws_sns_topic" "alerts" {
  name = "CoNote-CSPM-Alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.acct } }
      },
      {
        Sid       = "CloudWatchPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { StringEquals = { "aws:SourceAccount" = local.acct } }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })
}

# ---- A. Periodic: alarms on metrics published by scripts/publish-metrics.sh
resource "aws_cloudwatch_metric_alarm" "critical_findings" {
  alarm_name          = "CoNote-CSPM-Critical-Findings"
  alarm_description   = "Latest CSPM scan reports at least one CRITICAL finding"
  namespace           = "CoNote/CSPM"
  metric_name         = "CriticalFindings"
  statistic           = "Maximum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

resource "aws_cloudwatch_metric_alarm" "public_exposure" {
  alarm_name          = "CoNote-CSPM-Public-Exposure"
  alarm_description   = "Unintended public exposure detected (public SSH/RDP or S3 public access block incomplete)"
  namespace           = "CoNote/CSPM"
  metric_name         = "PublicExposure"
  statistic           = "Maximum"
  period              = 900
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# "Monitoring the monitor": if no scan has published anything for 2 hours,
# the scheduler is broken -> alert (missing data = breaching here).
resource "aws_cloudwatch_metric_alarm" "scan_heartbeat" {
  alarm_name          = "CoNote-CSPM-Scan-Missing"
  alarm_description   = "No CSPM scan result published for 2 hours - scheduler or credentials broken"
  namespace           = "CoNote/CSPM"
  metric_name         = "ScanCompleted"
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
}

# ---- B. Real-time: risky configuration changes, straight from CloudTrail
resource "aws_cloudwatch_event_rule" "risky_changes" {
  name        = "conote-cspm-risky-config-change"
  description = "Security group opened, S3 public access block removed or bucket policy/ACL changed"
  event_pattern = jsonencode({
    source      = ["aws.ec2", "aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = [
        "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules",
        "DeleteBucketPublicAccessBlock",
        "PutBucketPublicAccessBlock",
        "PutBucketPolicy",
        "PutBucketAcl",
        "DeleteBucketEncryption"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "risky_changes_sns" {
  rule      = aws_cloudwatch_event_rule.risky_changes.name
  target_id = "sns"
  arn       = aws_sns_topic.alerts.arn

  # A readable notification: what, who, from where, when, which resource.
  input_transformer {
    input_paths = {
      event   = "$.detail.eventName"
      who     = "$.detail.userIdentity.arn"
      ip      = "$.detail.sourceIPAddress"
      time    = "$.detail.eventTime"
      region  = "$.region"
      account = "$.account"
      sg      = "$.detail.requestParameters.groupId"
      bucket  = "$.detail.requestParameters.bucketName"
    }
    input_template = "\"[Co-note CSPM] RISKY CHANGE <event> in account <account> / <region> at <time> by <who> from <ip>. Security group: <sg> Bucket: <bucket>. Action: verify it was approved; otherwise follow the remediation runbook.\""
  }
}
