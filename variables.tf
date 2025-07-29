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

variable "secrets_manager_endpoint" {
  description = "Secrets Manager Endpoint to get/set secret"
  type        = string
}

variable "ses_smtp_endpoint" {
  description = "SES SMTP Endpoint to test new smtp credentials against"
  type        = string
}

variable "notification_sender_email" {
  description = "SES Verified identity/email address used in FROM field of notification email after rotation, if empty string function won't send notification of rotation"
  type        = string
  default     = ""
}

variable "notification_recipient_email" {
  description = "Email address to send notification email to after rotation"
  type        = string
  default     = ""
}

variable "smtp_iam_username" {
  description = "IAM Username for which to generate new SES SMTP credentials"
  type        = string
}

variable "ssm_rotation_document_name" {
  description = "SSM Document name to use with Command List for updating credentials on EC2 servers with ssm_server_tag_value, if empty string function won't attempt ssm:SendCommand"
  type        = string
  default     = ""
}

variable "ssm_commands_list" {
  description = "List of Commands to send to EC2 host via SSM in order to update credentials use"
  type        = list(string)
  default     = [""]
}

variable "ssm_rotate_on_ec2_instance_id" {
  description = "EC2 instance ID on which to execute SSM commands to rotate secret being used"
  type        = string
  default     = ""
}

variable "ssm_server_tag" {
  description = "Tag key used along with tag value to identify EC2 host to run SSM commands list against"
  type        = string
  default     = ""
}

variable "ssm_server_tag_value" {
  description = "Tag value used along with tag key to identify EC2 host to run SSM commands list against"
  type        = string
  default     = ""
}
