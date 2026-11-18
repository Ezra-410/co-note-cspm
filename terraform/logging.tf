# =============================================================================
# Audit logging: multi-region CloudTrail with log-file validation, encrypted
# with a customer-managed KMS key (rotation on). CloudTrail answers
# "WHO changed this security group / bucket, WHEN, from WHERE".
# =============================================================================
resource "aws_kms_key" "trail" {
  description             = "Co-note CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 7

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${local.acct}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "CloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = ["kms:GenerateDataKey*", "kms:DescribeKey"]
        Resource  = "*"
        Condition = {
          StringEquals = { "aws:SourceArn" = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${local.acct}:trail/conote-trail" }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${local.acct}:trail/*" }
        }
      },
      {
        Sid       = "AccountDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = ["kms:Decrypt", "kms:ReEncryptFrom"]
        Resource  = "*"
        Condition = {
          StringEquals = { "kms:CallerAccount" = local.acct }
          StringLike   = { "kms:EncryptionContext:aws:cloudtrail:arn" = "arn:${data.aws_partition.current.partition}:cloudtrail:*:${local.acct}:trail/*" }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "trail" {
  name          = "alias/conote-cloudtrail"
  target_key_id = aws_kms_key.trail.key_id
}

resource "aws_cloudtrail" "conote" {
  name                          = "conote-trail"
  s3_bucket_name                = aws_s3_bucket.this["trail"].id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.trail.arn

  depends_on = [aws_s3_bucket_policy.all]
}
