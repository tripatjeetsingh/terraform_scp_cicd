#-----security_controls_scp/modules/s3/deny_public_access_points.tf----#

data "aws_iam_policy_document" "terraform_consolidated_s3_policy" {

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

resource "aws_organizations_policy" "terraform_consolidated_s3_policy" {
  name        = "Terraform - consolidated S3 bucket service control policies"
  description = "Deny rules for s3 as per the approved UMB standards"

  content = data.aws_iam_policy_document.terraform_consolidated_s3_policy.json
}

resource "null_resource" "remove-scp" {
  provisioner "local-exec" {
    command = "aws organizations detach-policy --policy-id ${aws_organizations_policy.terraform_consolidated_s3_policy.id} --target-id ${var.target_id}"
  }
}

resource "aws_organizations_policy_attachment" "terraform_consolidated_s3_policy_attachment" {
  policy_id  = aws_organizations_policy.terraform_consolidated_s3_policy.id
  target_id  = var.target_id
  depends_on = ["null_resource.remove-scp"]
}
