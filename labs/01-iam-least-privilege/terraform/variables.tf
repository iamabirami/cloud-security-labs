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
  default     = "lab01"
}
