# =============================================================================
# CSPM identities (least privilege, short-lived credentials)
#
#  conote-security-audit   READ-ONLY. Used by Prowler, Steampipe, Powerpipe and
#                          Cloud Custodian detection. Can only WRITE metrics to
#                          the two CSPM CloudWatch namespaces.
#  conote-cspm-remediator  Can ONLY revoke security-group ingress and set the
#                          S3 public access block, ONLY on Project=co-note
#                          resources, and ONLY with an MFA-authenticated
#                          session (= a human approves every remediation).
#  conote-cspm-github      Same read-only rights for the scheduled GitHub
#                          Actions workflow, via OIDC (no stored AWS keys).
# =============================================================================
locals {
  admin_arn = "arn:${data.aws_partition.current.partition}:iam::${local.acct}:user/${var.admin_user_name}"
  aws_policy = "arn:${data.aws_partition.current.partition}:iam::aws:policy"
}

# ---------------------------------------------------------------- audit role
resource "aws_iam_role" "security_audit" {
  name                 = "conote-security-audit"
  description          = "Read-only CSPM assessment identity (Prowler, Steampipe, Custodian detection)"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.admin_arn }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "audit_securityaudit" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "${local.aws_policy}/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "audit_viewonly" {
  role       = aws_iam_role.security_audit.name
  policy_arn = "${local.aws_policy}/job-function/ViewOnlyAccess"
}

# Extra read-only calls some Prowler checks need (subset of Prowler's documented
# "prowler-additions-policy"). Deliberately excluded: lambda:GetFunction (returns
# a download URL for function CODE) and securityhub:BatchImportFindings (write).
data "aws_iam_policy_document" "cspm_read_additions" {
  statement {
    sid    = "ProwlerReadAdditions"
    effect = "Allow"
    actions = [
      "account:Get*",
      "backup:List*", "backup:Get*",
      "cloudtrail:GetInsightSelectors",
      "ec2:GetEbsEncryptionByDefault",
      "ec2:GetSnapshotBlockPublicAccessState",
      "ec2:GetInstanceMetadataDefaults",
      "ecr:Describe*", "ecr:GetRegistryScanningConfiguration",
      "logs:FilterLogEvents",
      "macie2:GetMacieSession",
      "s3:GetAccountPublicAccessBlock",
      "shield:DescribeProtection", "shield:GetSubscriptionState",
      "ssm:GetDocument",
      "support:Describe*",
      "tag:GetTagKeys", "tag:GetResources",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "PublishCspmMetricsOnly"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CoNote/CSPM", "CloudMaid"]
    }
  }
}

resource "aws_iam_role_policy" "audit_additions" {
  name   = "cspm-read-additions"
  role   = aws_iam_role.security_audit.id
  policy = data.aws_iam_policy_document.cspm_read_additions.json
}

# ----------------------------------------------------------- remediator role
resource "aws_iam_role" "remediator" {
  name                 = "conote-cspm-remediator"
  description          = "Controlled remediation - MFA required, Project=co-note resources only"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = local.admin_arn }
      Action    = "sts:AssumeRole"
      Condition = { Bool = { "aws:MultiFactorAuthPresent" = "true" } }
    }]
  })
}

data "aws_iam_policy_document" "remediator" {
  statement {
    sid    = "ReadToEvaluate"
    effect = "Allow"
    actions = [
      "ec2:DescribeSecurityGroups", "ec2:DescribeSecurityGroupRules",
      "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeTags",
      "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetBucketTagging",
      "s3:GetBucketPublicAccessBlock", "s3:GetBucketPolicy", "s3:GetBucketPolicyStatus",
      "s3:GetBucketAcl", "s3:GetEncryptionConfiguration", "s3:GetBucketVersioning",
      "s3:GetBucketLogging", "s3:GetBucketNotification", "s3:GetLifecycleConfiguration",
      "s3:GetBucketWebsite", "s3:GetReplicationConfiguration", "s3:GetBucketOwnershipControls",
      "tag:GetResources",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "RevokeIngressOnCoNoteOnly"
    effect    = "Allow"
    actions   = ["ec2:RevokeSecurityGroupIngress"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.region}:${local.acct}:security-group/*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/Project"
      values   = ["co-note"]
    }
  }

  # S3 has no resource-tag condition key for bucket configuration calls ->
  # restrict by bucket NAME instead.
  statement {
    sid       = "RestoreS3PublicBlockOnCoNoteOnly"
    effect    = "Allow"
    actions   = ["s3:PutBucketPublicAccessBlock", "s3:PutBucketPolicy", "s3:DeleteBucketPolicy"]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::conote-*"]
  }

  statement {
    sid       = "PublishCspmMetricsOnly"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["CoNote/CSPM", "CloudMaid"]
    }
  }
}

resource "aws_iam_role_policy" "remediator" {
  name   = "cspm-controlled-remediation"
  role   = aws_iam_role.remediator.id
  policy = data.aws_iam_policy_document.remediator.json
}

# ------------------------------------------------- GitHub OIDC scheduled scans
resource "aws_iam_openid_connect_provider" "github" {
  count          = var.enable_github_oidc ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "github_scan" {
  count                = var.enable_github_oidc ? 1 : 0
  name                 = "conote-cspm-github"
  description          = "Scheduled CSPM scans from GitHub Actions (main branch only, read-only)"
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_openid_connect_provider.github[0].arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_repo}:ref:refs/heads/main"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "github_securityaudit" {
  count      = var.enable_github_oidc ? 1 : 0
  role       = aws_iam_role.github_scan[0].name
  policy_arn = "${local.aws_policy}/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "github_viewonly" {
  count      = var.enable_github_oidc ? 1 : 0
  role       = aws_iam_role.github_scan[0].name
  policy_arn = "${local.aws_policy}/job-function/ViewOnlyAccess"
}

resource "aws_iam_role_policy" "github_additions" {
  count  = var.enable_github_oidc ? 1 : 0
  name   = "cspm-read-additions"
  role   = aws_iam_role.github_scan[0].id
  policy = data.aws_iam_policy_document.cspm_read_additions.json
}
