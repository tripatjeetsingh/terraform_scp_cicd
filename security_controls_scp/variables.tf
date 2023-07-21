#-----security_controls_scp/variables.tf----#
variable "target_id" {
  description = "The Root ID, Organizational Unit ID, or AWS Account ID to apply SCPs."
  type        = list(string)
}

variable "region_lockdown" {
  description = "The AWS region(s) you want to restrict resources to."
  type        = list(string)
}

variable "imdsv2_max_hop" {
  description = "The maximum hop allowed for an IMDSv2 token."
  default     = 1
  type        = number
}
