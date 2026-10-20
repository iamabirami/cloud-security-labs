data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------------------
# 1. A private, encrypted S3 bucket holding "sensitive" test data.
#    This is the resource we want to grant tightly scoped access to.
# ---------------------------------------------------------------------------
resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "data" {
  bucket        = "${var.name_prefix}-reports-${random_id.suffix.hex}"
  force_destroy = true # lab only: lets `terraform destroy` empty the bucket
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_object" "sample" {
  bucket  = aws_s3_bucket.data.id
  key     = "reports/q3-summary.txt"
  content = "Sample report for IAM lab testing. Not real data."
}

# ---------------------------------------------------------------------------
# 2. Permission boundary: the MAXIMUM permissions this user can ever have,
#    even if someone later attaches AdministratorAccess to them.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "boundary" {
  statement {
    sid       = "AllowReadReportsBucketOnly"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
  }

  statement {
    sid    = "AllowSelfServiceMfa"
    effect = "Allow"
    actions = [
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:ChangePassword",
      "sts:GetSessionToken",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "DenyPrivilegeEscalation"
    effect = "Deny"
    actions = [
      "iam:CreatePolicy*",
      "iam:AttachUserPolicy",
      "iam:PutUserPolicy",
      "iam:DeleteUserPermissionsBoundary",
      "iam:PutUserPermissionsBoundary",
      "iam:CreateAccessKey",
      "iam:AddUserToGroup",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "boundary" {
  name        = "${var.name_prefix}-analyst-boundary"
  description = "Permission boundary: caps analyst access to read-only on the reports bucket."
  policy      = data.aws_iam_policy_document.boundary.json
}

# ---------------------------------------------------------------------------
# 3. Identity policy: what the analyst is actually granted.
#    Read the reports bucket, but ONLY when signed in with MFA.
# ---------------------------------------------------------------------------
data "aws_iam_policy_document" "analyst" {
  statement {
    sid       = "ReadReportsWithMfa"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }

  statement {
    sid    = "ManageOwnMfa"
    effect = "Allow"
    actions = [
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:ChangePassword",
    ]
    resources = [
      "arn:aws:iam::${local.account_id}:user/$${aws:username}",
      "arn:aws:iam::${local.account_id}:mfa/$${aws:username}",
    ]
  }

  # The console's MFA set-up screen lists devices account-wide; this action
  # does not support resource-level scoping.
  statement {
    sid       = "ListVirtualMfaDevices"
    effect    = "Allow"
    actions   = ["iam:ListVirtualMFADevices"]
    resources = ["*"]
  }

  # Belt and braces: explicitly deny everything else until MFA is used.
  statement {
    sid    = "DenyAllWithoutMfa"
    effect = "Deny"
    not_actions = [
      "iam:GetUser",
      "iam:ListMFADevices",
      "iam:ListVirtualMFADevices",
      "iam:CreateVirtualMFADevice",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:ChangePassword",
      "sts:GetSessionToken",
    ]
    resources = ["*"]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }
  }
}

resource "aws_iam_policy" "analyst" {
  name        = "${var.name_prefix}-analyst-read-reports"
  description = "Read-only access to the reports bucket, MFA required."
  policy      = data.aws_iam_policy_document.analyst.json
}

# ---------------------------------------------------------------------------
# 4. Group-based access: permissions go on the group, never the user.
# ---------------------------------------------------------------------------
resource "aws_iam_group" "analysts" {
  name = "${var.name_prefix}-analysts"
}

resource "aws_iam_group_policy_attachment" "analysts" {
  group      = aws_iam_group.analysts.name
  policy_arn = aws_iam_policy.analyst.arn
}

resource "aws_iam_user" "analyst" {
  name                 = "${var.name_prefix}-analyst"
  permissions_boundary = aws_iam_policy.boundary.arn
  force_destroy        = true
}

resource "aws_iam_user_group_membership" "analyst" {
  user   = aws_iam_user.analyst.name
  groups = [aws_iam_group.analysts.name]
}
