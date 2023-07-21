#-----security_controls_scp/modules/s3/deny_public_access_points.tf----#
# This is the first set of service control policies consolidated into one policy document 'baseline guardrail policy-1' 
data "aws_iam_policy_document" "umb_security_guardrails_2" {

  statement {
    sid       = "donotattachedfulladminprivileges"
    effect    = "Deny"
    resources = ["*", ]

    actions = [
      "iam:PutUserPolicy",
      "iam:PutGroupPolicy",
      "iam:PutRolePolicy",
    ]

    condition {
      test     = "StringLike"
      variable = "iam:PolicyDocument.Statement.Action"
      values   = ["*:*", ]
    }
  }
  statement {
    sid    = "Denyattachuserpolicy"
    effect = "Deny"
    actions = [
      "iam:AttachUserPolicy",
    ]
    resources = ["*", ]
  }
  statement {
    sid    = "deniescreationofrootuseraccesskeys"
    effect = "Deny"
    actions = [
      "iam:CreateAccessKey",
    ]
    resources = [
      "arn:aws:iam::*:root",
    ]
  }

  statement {
    sid       = "Preventtherootuserfromperforminganyactions"
    effect    = "Deny"
    resources = ["*"]
    actions   = ["*"]

    condition {
      test     = "ArnLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::*:root"]
    }
  }
  statement {
    sid       = "DenymostActionsWithoutMFA"
    effect    = "Deny"
    resources = ["*"]

    not_actions = [
      "iam:CreateVirtualMFADevice",
      "iam:DeleteVirtualMFADevice",
      "iam:ListVirtualMFADevices",
      "iam:EnableMFADevice",
      "iam:ResyncMFADevice",
      "iam:ListAccountAliases",
      "iam:ListUsers",
      "iam:ListSSHPublicKeys",
      "iam:ListAccessKeys",
      "iam:ListServiceSpecificCredentials",
      "iam:ListMFADevices",
      "iam:GetAccountSummary",
      "sts:GetSessionToken",
    ]

    condition {
      test     = "BoolIfExists"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["false"]
    }

    condition {
      test     = "BoolIfExists"
      variable = "aws:ViaAWSService"
      values   = ["false"]
    }
  }
  # statement {
  #   sid = "Preventlogsmodification"
  #   effect = "Deny"
  #   actions = [
  #     "cloudtrail:DeleteTrail",
  #     "cloudtrail:StopLogging",
  #     "ec2:DeleteFlowlogs",
  #     "logs:DeleteLogGroup",
  #     "logs:DeleteLogStream"
  #   ]

  #   resources = [
  #     "*",
  #   ]
  # }
  # statement {
  #   sid       = "Preventguarddutymodification"
  #   effect    = "Deny"
  #   resources = ["*"]
  #   actions   = [
  #        "guardduty:DeclineInvitations",
  #        "guardduty:DeleteDetector",
  #        "guardduty:CreateIPSet",
  #        "guardduty:DisassociateFromMasterAccount",
  #        "guardduty:UpdateDetector",
  #        ]
  # }
  # statement {
  #   sid       = "Preventconfigmodification"
  #   effect    = "Deny"
  #   resources = ["*"]
  #   actions   = [
  #        "config:DeleteConfigRule",
  #        "config:DeleteConfigurationRecorder",
  #        "config:DeleteDeliveryChannel",
  #        "config:StopConfigurationRecorder"
  #        ]
  # }
  # statement {
  #   sid = "DenyCloudTrailActions"
  #   effect = "Deny"
  #   actions = [
  #     "cloudtrail:DeleteTrail",
  #     "cloudtrail:PutEventSelectors",
  #     "cloudtrail:StopLogging",
  #     "cloudtrail:UpdateTrail",
  #     "cloudtrail:RemovedTags"
  #   ]

  #   resources = [
  #     "arn:aws:s3:::aws-controltower-logs-xxxxxxxxxxxx-us-east-2*",
  #   ]
  # }
  statement {
    sid = "RequireIMDSv2"

    actions = [
      "ec2:RunInstances"
    ]

    resources = [
      "arn:aws:ec2:*:*:instance/*",
    ]

    effect = "Deny"

    condition {
      test     = "StringNotEquals"
      variable = "ec2:MetadataHttpTokens"

      values = [
        "required",
      ]
    }
  }
  statement {
    sid = "IMDSv2MaxHopLimit"

    actions = [
      "ec2:RunInstances"
    ]

    resources = [
      "arn:aws:ec2:*:*:instance/*",
    ]

    effect = "Deny"

    condition {
      test     = "NumericGreaterThan"
      variable = "ec2:MetadataHttpPutResponseHopLimit"

      values = [
        var.imdsv2_max_hop,
      ]
    }
  }
  statement {
    sid = "RequireEC2snapshotencryption"

    actions = [
      "ec2:ImportSnapshot",
      "ec2:CreateSnapshot",
      "ec2:RestoreSnapshotFromRecycleBin",
      "ec2:RestoreSnapshotTier"
    ]

    resources = [
      "arn:aws:ec2:*:*:snapshot/*",
    ]

    effect = "Deny"

    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"

      values = [
        "false",
      ]
    }
  }
  statement {
    sid = "Requireec2volumeencryption"

    actions = [
      "ec2:AttachVolume",
      "ec2:CreateVolumet",
      "ec2:ImportInstance",
      "ec2:RunInstance"
    ]

    resources = [
      "arn:aws:ec2:*:*:Volume/*",
    ]

    effect = "Deny"

    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"

      values = [
        "false",
      ]
    }
  }
  statement {
    sid = "DenyEc2PublicIp"

    actions = [
      "ec2:RunInstances",
    ]

    resources = [
      "arn:aws:ec2:*:*:network-interface/*",
    ]

    effect = "Deny"

    condition {
      test     = "Bool"
      variable = "ec2:AssociatePublicIpAddress"

      values = [
        "true",
      ]
    }
  }
  statement {
    sid = "DenyDirectInternetNotebook"

    actions = [
      "sagemaker:CreateNotebookInstance",
    ]

    resources = [
      "*",
    ]

    effect = "Deny"

    condition {
      test     = "StringNotEquals"
      variable = "sagemaker:DirectInternetAccess"

      values = [
        "Disabled",
      ]
    }
  }
  statement {
    sid = "DenyRootAccess"

    actions = [
      "sagemaker:CreateNotebookInstance",
      "sagemaker:UpdateNotebookInstance",
    ]

    resources = [
      "*",
    ]

    effect = "Deny"

    condition {
      test     = "StringNotEquals"
      variable = "sagemaker:RootAccess"

      values = [
        "Enabled",
      ]
    }
  }
  statement {
    sid = "RequiresallSageMakerDomainstoroutetrafficthroughVPCs"

    actions = [
      "sagemaker:CreateDomain",
    ]

    resources = [
      "*",
    ]

    effect = "Deny"

    condition {
      test     = "StringEquals"
      variable = "sagemaker:AppNetworkAccessType"

      values = [
        "PublicInternetOnly",
      ]
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
    sid    = "DenyVpcFlowDelete"
    effect = "Deny"
    actions = [
      "ec2:DeleteFlowLogs",
      "logs:DeleteLogGroup",
      "logs:DeleteLogStream",
    ]

    resources = [
      "*",
    ]
  }
  statement {
    sid = "RequireS3SecureTransort"

    actions = [
      "s3:Put*",
    ]

    resources = ["*", ]

    effect = "Deny"

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"

      values = [
        "True",
      ]
    }
  }
  # statement {
  #   sid       = "preventmodificationofs3bucketpolicy"
  #   effect    = "Deny"
  #   actions = [
  #     "s3:PutBucketPolicy",
  #     "s3:PutReplicationConfiguration",
  #   ]
  #   resources = ["arn:aws:s3:::your-bucket-name/*"]

  #    condition {
  #     test     = "StringNotLike"
  #     variable = "aws:PrincipalArn"
  #     values   = ["arn:aws:iam::*:role/*"]
  #   }
  # }
  statement {
    sid       = "s3blockpublicaccess"
    effect    = "Deny"
    resources = ["arn:aws:s3:::*"]
    actions   = ["s3:PutBucketPublicAccessBlock"]

    condition {
      test     = "StringEquals"
      variable = "s3:PublicAccessBlockConfiguration"
      values = [
        "true",
      ]
    }
  }
  statement {
    sid = "Requiresefsencryption"

    actions = [
      "elasticfilesystem:CreateFileSystem",
    ]

    resources = ["*", ]

    effect = "Deny"

    condition {
      test     = "Bool"
      variable = "elasticfilesystem:Encrypted"

      values = [
        "false",
      ]
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
    sid    = "DenyDeletionOfCloudTrailS3Buckets"
    effect = "Deny"
    actions = [
      "s3:Delete*"
    ]
    resources = [
      "arn:aws:s3:::aws-controltower-logs-xxxxxxxxxxxx-us-east-2*"
    ]
  }
  statement {
    sid       = "preventDeletionOfKMS"
    effect    = "Deny"
    resources = ["*"]
    actions = [
      "kms:UntagResource",
      "kms:Delete*",
      "kms:ScheduleKeyDeletion"

    ]
  }
}

resource "aws_organizations_policy" "umb_security_guardrails_2" {
  name        = "UMB - Consolidated Security Control Baseline Guardrails-2"
  description = "Policy document to establish baseline security control guardrails for the UMB AWS environment"

  content = data.aws_iam_policy_document.umb_security_guardrails_2.json
}

resource "aws_organizations_policy_attachment" "umb_security_guardrails_2_attachment" {
  policy_id = aws_organizations_policy.umb_security_guardrails_2.id
  count     = length(var.target_id)
  target_id = var.target_id[count.index]
}
