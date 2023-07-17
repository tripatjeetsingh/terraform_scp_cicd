#-----security_controls_scp/variables.tf----#
#variable "target_id" {
#  description = "The Root ID, Organizational Unit ID, or AWS Account ID to apply SCPs."
#  type        = string
#}

#variable "target_id" {
#  description = "The Root ID, Organizational Unit ID, or AWS Account ID to apply SCPs."
#  type        = map(string)
#  default = {
#    workload      = "ou-zv9n-89jvfe4l",
#    workload-qa   = "ou-zv9n-gdvk0rvw",
#    workload-prod = "ou-zv9n-s9vrqpio",
#  }
#}

variable "target_id" {
  description = "The Root ID, Organizational Unit ID, or AWS Account ID to apply SCPs."
  type        = list(string)
  default = []
}

variable "region_lockdown" {
  description = "The AWS region(s) you want to restrict resources to."
  type        = list(string)
  default = [
    "us-east-2",
  ]
}
