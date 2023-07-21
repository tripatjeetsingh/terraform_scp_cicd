# This is the first set of service control policies consolidated into one policy document 'baseline guardrail policy-1'
data "aws_iam_policy_document" "umb_security_guardrails_2" {
  statement {
    sid       = "Requireec2volumeencryption"
    actions   = ["ec2:AttachVolume", "ec2:CreateVolumet", "ec2:ImportInstance", "ec2:RunInstance"]
    resources = ["arn:aws:ec2:*:*:Volume/*", ]
    effect    = "Deny"
    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"
      values   = ["false", ]
    }
  }
  statement {
    sid       = "DenyEc2PublicIp"
    actions   = ["ec2:RunInstances", ]
    resources = ["arn:aws:ec2:*:*:network-interface/*", ]
    effect    = "Deny"
    condition {
      test     = "Bool"
      variable = "ec2:AssociatePublicIpAddress"
      values   = ["true", ]
    }
  }
  statement {
    sid       = "DenyDirectInternetNotebook"
    actions   = ["sagemaker:CreateNotebookInstance", ]
    resources = ["*", ]
    effect    = "Deny"
    condition {
      test     = "StringNotEquals"
      variable = "sagemaker:DirectInternetAccess"
      values   = ["Disabled", ]
    }
  }
  statement {
    sid       = "DenyRootAccess"
    actions   = ["sagemaker:CreateNotebookInstance", "sagemaker:UpdateNotebookInstance", ]
    resources = ["*", ]
    effect    = "Deny"
    condition {
      test     = "StringNotEquals"
      variable = "sagemaker:RootAccess"
      values   = ["Enabled", ]
    }
  }
  statement {
    sid       = "RequiresallSageMakerDomainstoroutetrafficthroughVPCs"
    actions   = ["sagemaker:CreateDomain", ]
    resources = ["*", ]
    effect    = "Deny"
    condition {
      test     = "StringEquals"
      variable = "sagemaker:AppNetworkAccessType"
      values   = ["PublicInternetOnly", ]
    }
  }
  statement {
    sid       = "PreventdisablingdefaultEBSencryption"
    effect    = "Deny"
    resources = ["*"]
    actions   = ["ec2:DisableEbsEncryptionByDefault"]
    condition {
      test     = "ArnNotLike"
      variable = "aws:PrincipalARN"
      values   = ["arn:aws:iam::*:role/[ALLOWED_ROLE_NAME]"]
    }
  }
  statement {
    sid       = "DenyVpcFlowDelete"
    effect    = "Deny"
    actions   = ["ec2:DeleteFlowLogs", "logs:DeleteLogGroup", "logs:DeleteLogStream", ]
    resources = ["*", ]
  }
  statement {
    sid       = "RequireS3SecureTransort"
    actions   = ["s3:Put*", ]
    resources = ["*", ]
    effect    = "Deny"
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["True", ]
    }
  }
  statement {
    sid       = "s3blockpublicaccess"
    effect    = "Deny"
    resources = ["arn:aws:s3:::*"]
    actions   = ["s3:PutBucketPublicAccessBlock"]
    condition {
      test     = "StringEquals"
      variable = "s3:PublicAccessBlockConfiguration"
      values   = ["true", ]
    }
  }
  statement {
    sid       = "Requiresefsencryption"
    actions   = ["elasticfilesystem:CreateFileSystem", ]
    resources = ["*", ]
    effect    = "Deny"
    condition {
      test     = "Bool"
      variable = "elasticfilesystem:Encrypted"
      values   = ["false", ]
    }
  }
  statement {
    sid       = "requireS3encryptedObjectUploads"
    effect    = "Deny"
    resources = ["*"]
    actions   = ["s3:PutObject"]
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }
  statement {
    sid       = "DenyDeletionOfCloudTrailS3Buckets"
    effect    = "Deny"
    actions   = ["s3:Delete*"]
    resources = ["arn:aws:s3:::aws-controltower-logs-xxxxxxxxxxxx-us-east-2*"]
  }
  statement {
    sid       = "preventDeletionOfKMS"
    effect    = "Deny"
    resources = ["*"]
    actions   = ["kms:UntagResource", "kms:Delete*", "kms:ScheduleKeyDeletion"]
  }
}
resource "aws_organizations_policy" "umb_security_guardrails_2" {
  name        = "UMB - Consolidated Security Control Baseline Guardrails-2"
  description = "Policy document to establish baseline security control guardrails for the UMB AWS environment"
  content     = data.aws_iam_policy_document.umb_security_guardrails_2.json
}
resource "aws_organizations_policy_attachment" "umb_security_guardrails_2_attachment" {
  policy_id = aws_organizations_policy.umb_security_guardrails_2.id
  count     = length(var.target_id)
  target_id = var.target_id[count.index]
}
