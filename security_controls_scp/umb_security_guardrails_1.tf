# This is the first set of service control policies consolidated into one policy document 'baseline guardrail policy-1'
data "aws_iam_policy_document" "umb_security_guardrails_1" {
  statement {
    sid       = "DoNotAttachedFullAdminPrivileges"
    effect    = "Deny"
    resources = ["*", ]
    actions   = ["iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy", ]
    condition {
      test     = "StringLike"
      variable = "iam:PolicyDocument.Statement.Action"
      values   = ["*:*", ]
    }
  }
  statement {
    sid       = "DenyAttachUserPolicy"
    effect    = "Deny"
    actions   = ["iam:AttachUserPolicy", ]
    resources = ["*", ]
  }
  statement {
    sid       = "DeniesCreationOfrootuseraccesskeys"
    effect    = "Deny"
    actions   = ["iam:CreateAccessKey", ]
    resources = ["arn:aws:iam::*:root", ]
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
    sid         = "DenymostActionsWithoutMFA"
    effect      = "Deny"
    resources   = ["*"]
    not_actions = ["iam:CreateVirtualMFADevice", "iam:DeleteVirtualMFADevice", "iam:ListVirtualMFADevices", "iam:EnableMFADevice", "iam:ResyncMFADevice", "iam:ListAccountAliases", "iam:ListUsers", "iam:ListSSHPublicKeys", "iam:ListAccessKeys", "iam:ListServiceSpecificCredentials", "iam:ListMFADevices", "iam:GetAccountSummary", "sts:GetSessionToken", ]
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
  statement {
    sid       = "RequireIMDSv2"
    actions   = ["ec2:RunInstances", ]
    resources = ["arn:aws:ec2:*:*:instance/*", ]
    effect    = "Deny"
    condition {
      test     = "StringNotEquals"
      variable = "ec2:MetadataHttpTokens"
      values   = ["required", ]
    }
  }
  statement {
    sid       = "IMDSv2MaxHopLimit"
    actions   = ["ec2:RunInstances", ]
    resources = ["arn:aws:ec2:*:*:instance/*", ]
    effect    = "Deny"
    condition {
      test     = "NumericGreaterThan"
      variable = "ec2:MetadataHttpPutResponseHopLimit"
      values   = [var.imdsv2_max_hop, ]
    }
  }
  statement {
    sid       = "RequireEC2SnapshotEncryption"
    actions   = ["ec2:ImportSnapshot", "ec2:CreateSnapshot", "ec2:RestoreSnapshotFromRecycleBin", "ec2:RestoreSnapshotTier"]
    resources = ["arn:aws:ec2:*:*:snapshot/*", ]
    effect    = "Deny"
    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"
      values   = ["false", ]
    }
  }
  statement {
    sid       = "RequireEC2SnapshotEncryption"
    actions   = ["ec2:ImportSnapshot", "ec2:CreateSnapshot", "ec2:RestoreSnapshotFromRecycleBin", "ec2:RestoreSnapshotTier"]
    resources = ["arn:aws:ec2:*:*:snapshot/*", ]
    effect    = "Deny"
    condition {
      test     = "Bool"
      variable = "ec2:Encrypted"
      values   = ["false", ]
    }
  }
}
resource "aws_organizations_policy" "umb_security_guardrails_1" {
  name        = "UMB - Consolidated Security Control Baseline Guardrails-1"
  description = "Policy document to establish baseline security control guardrails for the UMB AWS environment"
  content     = data.aws_iam_policy_document.umb_security_guardrails_1.json
}
resource "aws_organizations_policy_attachment" "umb_security_guardrails_1_attachment" {
  policy_id = aws_organizations_policy.umb_security_guardrails_1.id
  count     = length(var.target_id)
  target_id = var.target_id[count.index]
}
