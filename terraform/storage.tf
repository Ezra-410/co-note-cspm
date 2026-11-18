# =============================================================================
# Storage: 3 Co-note buckets + 1 access-log bucket. All private by design:
#   public access block (4 settings), encryption, versioning, TLS-only policy,
#   bucket-owner-enforced ownership (ACLs disabled), server access logging.
# The drift simulation later switches OFF the public access block of the
# uploads bucket "by hand", outside Terraform.
# =============================================================================
locals {
  acct = data.aws_caller_identity.current.account_id
  buckets = {
    uploads = "conote-uploads-${local.acct}"
    backups = "conote-backups-${local.acct}"
    trail   = "conote-cloudtrail-${local.acct}"
  }
}

# Account-level S3 public access block is intentionally NOT set: with it ON, a
# bucket-level drift could never become a real exposure, and the lab exercise
# would detect nothing. Recorded as an accepted lab exception (EXC-L01).

resource "aws_s3_bucket" "logs" {
  bucket        = "conote-access-logs-${local.acct}"
  force_destroy = true
  tags          = { Name = "conote-access-logs", DataClass = "logs" }
}

resource "aws_s3_bucket" "this" {
  for_each      = local.buckets
  bucket        = each.value
  force_destroy = true
  tags          = { Name = "conote-${each.key}", DataClass = each.key == "trail" ? "audit" : "confidential" }
}

locals {
  all_buckets = merge({ for k, b in aws_s3_bucket.this : k => b }, { logs = aws_s3_bucket.logs })
}

resource "aws_s3_bucket_public_access_block" "all" {
  for_each                = local.all_buckets
  bucket                  = each.value.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "all" {
  for_each = local.all_buckets
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "all" {
  for_each = local.all_buckets
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "all" {
  for_each = local.all_buckets
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "data" {
  for_each      = aws_s3_bucket.this
  bucket        = each.value.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "${each.key}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }
}

# --- bucket policies: TLS only (+ CloudTrail / log delivery where needed) ---
data "aws_iam_policy_document" "tls_only" {
  for_each = local.all_buckets

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      each.value.arn,
      "${each.value.arn}/*",
    ]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  dynamic "statement" {
    for_each = each.key == "trail" ? [1] : []
    content {
      sid       = "CloudTrailAclCheck"
      effect    = "Allow"
      actions   = ["s3:GetBucketAcl"]
      resources = [each.value.arn]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${local.acct}:trail/conote-trail"]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "trail" ? [1] : []
    content {
      sid       = "CloudTrailWrite"
      effect    = "Allow"
      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/AWSLogs/${local.acct}/*"]
      principals {
        type        = "Service"
        identifiers = ["cloudtrail.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceArn"
        values   = ["arn:${data.aws_partition.current.partition}:cloudtrail:${var.region}:${local.acct}:trail/conote-trail"]
      }
    }
  }

  dynamic "statement" {
    for_each = each.key == "logs" ? [1] : []
    content {
      sid       = "S3ServerAccessLogs"
      effect    = "Allow"
      actions   = ["s3:PutObject"]
      resources = ["${each.value.arn}/*"]
      principals {
        type        = "Service"
        identifiers = ["logging.s3.amazonaws.com"]
      }
      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [local.acct]
      }
    }
  }
}

resource "aws_s3_bucket_policy" "all" {
  for_each = local.all_buckets
  bucket   = each.value.id
  policy   = data.aws_iam_policy_document.tls_only[each.key].json

  depends_on = [aws_s3_bucket_public_access_block.all]
}
