variable "aws_region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-west-2" # London
}

variable "aws_profile" {
  description = "Named AWS CLI profile to use. Keeps credentials out of code."
  type        = string
  default     = "sandbox"
}

variable "name_prefix" {
  description = "Prefix for all resource names in this lab."
  type        = string
  default     = "lab02"
}

variable "alert_email" {
  description = "Email address that receives security alerts. Set it in terraform.tfvars, never in code."
  type        = string
}

variable "guardduty_min_severity" {
  description = "Lowest GuardDuty severity that triggers an email (1-8.9). 4 = Medium and above."
  type        = number
  default     = 4
}
