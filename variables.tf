variable "project_name" {
  description = "Project name to prefix resources with"
  type        = string
}

variable "dry_run" {
  description = "Boolean toggle to control the dry-run mode of the lambda function"
  type        = bool
  default     = true
}

variable "lambda" {
  description = "Object of optional attributes passed on to the lambda module"
  type = object({
    artifacts_dir            = optional(string, "builds")
    build_in_docker          = optional(bool, false)
    create_package           = optional(bool, true)
    ephemeral_storage_size   = optional(number)
    ignore_source_code_hash  = optional(bool, true)
    local_existing_package   = optional(string)
    memory_size              = optional(number, 128)
    recreate_missing_package = optional(bool, false)
    runtime                  = optional(string, "python3.12")
    s3_bucket                = optional(string)
    s3_existing_package      = optional(map(string))
    s3_prefix                = optional(string)
    store_on_s3              = optional(bool, false)
    timeout                  = optional(number, 300)
  })
  default = {}
}

variable "log_level" {
  description = "Log level for lambda"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], var.log_level)
    error_message = "Valid values for log level are (CRITICAL, ERROR, WARNING, INFO, DEBUG)."
  }
}

variable "tags" {
  description = "Tags for resource"
  type        = map(string)
  default     = {}
}

variable "ses_smtp_endpoint" {
  description = "SES SMTP Endpoint to test new smtp credentials against"
  type        = string
}

variable "notification_sender_email" {
  description = "SES Verified identity/email address used in FROM field of notification email after rotation, if empty string function won't try to send SES notification of rotation using new rotated credentials"
  type        = string
  default     = ""
}

variable "notification_recipient_email" {
  description = "Email address to send notification email to, if unset will not create SNS subscription"
  type        = string
  default     = ""
}

variable "smtp_iam_username" {
  description = "IAM Username for which to generate new SES SMTP credentials"
  type        = string
}

variable "ssm_rotation_document_name" {
  description = "SSM Document name (ie AWS-RunShellScript) to use with Command List for updating credentials on EC2 instance id provided"
  type        = string
  default     = "AWS-RunShellScript"
}

variable "ssm_rotate_on_ec2_instance_id" {
  description = "EC2 instance ID (ie i-xxxxxxxxxxxxxxxxx) on which to execute SSM commands to rotate secret being used, if empty string provided, function won't attempt ssm:SendCommand"
  type        = string
  default     = ""
}
