variable "aws_region" {
  description = "AWS region for TrailWeaver resources."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Lowercase prefix used for resource names."
  type        = string
  default     = "trailweaver"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,30}$", var.name_prefix))
    error_message = "name_prefix must be 3-31 lowercase letters, digits, or hyphens and start with a letter."
  }
}

variable "vpc_id" {
  description = "Existing VPC in which the runtime and EFS mount targets will run."
  type        = string
}

variable "application_subnet_ids" {
  description = "Existing subnet IDs for the future ECS task and EFS mount targets; use one subnet per availability zone."
  type        = set(string)

  validation {
    condition     = length(var.application_subnet_ids) >= 2
    error_message = "application_subnet_ids must contain at least two subnets in distinct availability zones."
  }
}

variable "cloudtrail_bucket_name" {
  description = "Name of an existing private bucket containing CloudTrail exports."
  type        = string

  validation {
    condition     = trimspace(var.cloudtrail_bucket_name) != ""
    error_message = "cloudtrail_bucket_name must not be empty."
  }
}

variable "cloudtrail_prefix" {
  description = "Non-empty object-key prefix TrailWeaver may list and read."
  type        = string

  validation {
    condition     = trim(var.cloudtrail_prefix, "/") != ""
    error_message = "cloudtrail_prefix must identify a non-empty portion of the bucket."
  }
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period."
  type        = number
  default     = 30

  validation {
    condition     = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365], var.log_retention_days)
    error_message = "log_retention_days must be a CloudWatch Logs supported retention value up to 365 days."
  }
}

variable "tags" {
  description = "Additional tags applied to supported resources."
  type        = map(string)
  default     = {}
}
