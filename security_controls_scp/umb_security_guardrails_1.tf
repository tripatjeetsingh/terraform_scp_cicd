#-----security_controls_scp/modules/s3/deny_public_access_points.tf----#
# This is the first set of service control policies consolidated into one policy document 'baseline guardrail policy-1' 
data "aws_iam_policy_document" "umb_security_guardrails_1" {

  statement {
    sid = "DenyReadWritePublicAccessBucketandAccount"
    actions = [
      "s3:PutAccountPublicAccessBlock",
      "s3:GetAccountPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicyStatus"
    ]
    resources = [
      "arn:aws:s3:::*/*",
    ]
    effect = "Deny"
  }

  statement {
    sid = "DenyPublicAccessPoints"

    actions = [
      "s3:CreateAccessPoint",
      "s3:PutAccessPointPolicy",
    ]
    resources = [
      "arn:aws:s3:*:*:accesspoint/*",
    ]
    effect = "Deny"
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:AccessPointNetworkOrigin"

      values = [
        "vpc",
      ]
    }
  }

  statement {
    sid = "DenyUnencryptedUploads"
    actions = [
      "s3:PutObject",
    ]
    resources = [
      "arn:aws:s3:::*/*",
    ]
    effect = "Deny"
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values = [
        "true",
      ]
    }
  }

  statement {
    sid = "DenyNoTLSRequests"

    actions = [
      "s3:*",
    ]

    resources = [
      "arn:aws:s3:::*/*",
    ]

    effect = "Deny"

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"

      values = [
        "false",
      ]
    }
  }
}

resource "aws_organizations_policy" "umb_security_guardrails_1" {
  name        = "UMB - Consolidated Security Control Baseline Guardrails-1"
  description = "Policy document to establish baseline security control guardrails for the UMB AWS environment"

  content = data.aws_iam_policy_document.umb_security_guardrails_1.json
}

resource "aws_organizations_policy_attachment" "umb_security_guardrails_1_attachment" {
  policy_id = aws_organizations_policy.umb_security_guardrails_1.id
  count     = length(var.target_id)
  target_id = var.target_id[count.index]
}
