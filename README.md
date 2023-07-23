# UMB - Terraform AWS Service Control Policies

This repository is a collection of AWS Service Control Policies (SCPs) written in Hashicorp Terraform to be used in UMB AWS Organizations.

UMB adopts three sources to establish a security control baseline for its AWS environment:

- CIS Amazon Web Services Foundations Benchmark (Current version 1.4)
- PCI-DSS (For accounts labled CDE)
- AWS Foundational Security Best Practices

These security controls are also referred to as guardrails.

Wherever possible, guardrails will be implemented on a preventative basis. These will take the form of either a Service Control Policy or AWS Config Rule with Auto-Remediation. Alternatively, a standard AWS Config Rule will be implemented when a preventative rule may not be technically possible or feasible. In these cases an alert and notification to the resource owner would be implemented in order for the control deviation to be corrected.


## About Service Control Policies

- For official documentation about SCPs, visit the links [here](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scp.html)
- SCPs enable you to restrict, at the account level of granularity, what services and actions the users, groups and roles in those accounts can do.
- SCPs are available only in an organization that has all features enabled. SCPs aren't available if your organization has enabled only the consolidated billing features.

## Considerations

- Best practice is to never attach SCPs to the root of your organization. Instead, create an Organizational Unit (OU) underneath root and attach policies there.
- SCPs do not grant permissions in IAM but instead allow/deny services or set security guardrails.
- Root user accounts are affected by SCPs.
- You must have at least one SCP attached to each entity.
- Maximum of 5 SCPs can be attached to the root, OU, or Account in an organization.

### Permission Logic

- If a user or role has an IAM permission policy that grants access to an action that is also allowed by the applicable SCPs, the user or role can perform that action.
- If a user or role has an IAM permission policy that grants access to an action that is either not allowed or explicitly denied by the applicable SCPs, the user or role can't perform that action.
- AWS Organizations use a tree hierarchy for SCPs. This means that if your account is in an Organizational Unit, it inherits that OUs policies.
- From the documentation:

![alt text](https://docs.aws.amazon.com/organizations/latest/userguide/images/How_SCP_Permissions_Work.png "SCP Venn Diagram")

## Content

- The [security_controls_scp](security_controls_scp/) folder is a grouping of AWS Security Best Practices to control at the AWS Organizations level.
  - __NOTICE:__ Due to the limitations of Service Control Policies, only a max of 5 may be attached at a given target OU. With that in mind, we have consolidated the security control policies into `umb_security_guardrails_1` and `umb_security_guardrails_2`. The maximum size for these SCPs policy documents is 5,120 bytes. You have a couple of options:
    - Select the `aws_iam_policy_document` you want and add/remove the policies.
    - With every policy addition, ensure that the size of the file does not exceed 5,120 bytes before you commit the code.
    - Add another `aws_iam_policy_document` and name it as `umb_security_guardrails_$sequence` if the other documents have already reached their max size.
  
## Usage

An example main.tf for the SCP module that will be applied to the target OU's defined in the variable target_id:

```hcl
module "security_controls_scp" {
  source = "./security_controls_scp"

  target_id       = var.target_id
  region_lockdown = var.region_lockdown
}
```
### Deployment

To Deploy all of the security control baseline policies, we use GitHub Actions workflow:
- In order to create the action workflow for push/pull request, the following terraform workflow `terraform_plan.yml` and `terraform_apply.yml` script is configured in the “.github/workflows directory.
- On execution of a GitHub push, it triggers the `terraform_plan.yml` workflow on the `featurebranch` & prepares the build, starts the terraform deployment lifecycle with “terraform init & plan” steps. The results appear as followed.
```
image.png
```
- When a new GitHub pull request is created, it initiates `terraform_apply.yml` action workflow on the `featurebranch`. Upon review and approval, starts the terraform deployment lifecycle with “terraform init & apply” steps to the `featurebranch`.
- The changes can now be merged to the `main` branch. It requires a peer approval and triggers the `terraform_apply.yml` workflow on the main branch 
```
image.png
```


### Deployment Dependencies

- [Terraform v12](https://www.terraform.io/downloads.html)
- [terraform-provider-aws](https://github.com/terraform-providers/terraform-provider-aws)
- An AWS Organization
- An IAM user with Organization Admin Access

## Common Errors

#### Enabled Policy Types

```
error creating Organizations Policy Attachment: PolicyTypeNotEnabledException: This operation can be performed only for enabled policy types.
status code: 400, request id: 2b8ecgeb-34h3-11e6-86fb-275c76986dec
```

SCP functionality must be enabled on the root.  See https://github.com/terraform-providers/terraform-provider-aws/issues/4545 for more information

#### Minimum SCP Requirement

```
aws_organizations_policy_attachment.deny_orgs_leave_attachment: ConstraintViolationException: You cannot remove the last policy attached to the specified target. You must have at least one attached at all times.
status code: 400, request id: 2d6c75b3-5757-13e9-ab76-518b756aebd3
```

You must have one SCP attached to an account or OU at all times. See: https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html for more information.

#### Conflicting Policy Attachment

```
error creating Organizations Policy Attachment: ConcurrentModificationException: AWS Organizations can't complete your request because it conflicts with another attempt to modify the same entity. Try again later. status code: 400, request id: h725f9g7-1234-12e9-h746-ch123ab12345
```
