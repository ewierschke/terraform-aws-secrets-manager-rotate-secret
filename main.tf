##############################
# Lambda
##############################
module "lambda" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v7.20.1"

  function_name = "${var.project_name}-rotate-ses-smtp-pass-secret"

  description = "Secrets Manager Rotate SES SMTP password ${var.project_name} by Lambda "
  handler     = "secrets_manager_ses_smtp_pass_lambda_rotation.lambda_handler"
  tags        = var.tags

  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda.json

  artifacts_dir            = var.lambda.artifacts_dir
  build_in_docker          = var.lambda.build_in_docker
  create_package           = var.lambda.create_package
  ephemeral_storage_size   = var.lambda.ephemeral_storage_size
  ignore_source_code_hash  = var.lambda.ignore_source_code_hash
  local_existing_package   = var.lambda.local_existing_package
  memory_size              = var.lambda.memory_size
  recreate_missing_package = var.lambda.recreate_missing_package
  runtime                  = var.lambda.runtime
  s3_bucket                = var.lambda.s3_bucket
  s3_existing_package      = var.lambda.s3_existing_package
  s3_prefix                = var.lambda.s3_prefix
  store_on_s3              = var.lambda.store_on_s3
  timeout                  = var.lambda.timeout

  source_path = [
    {
      path             = "${path.module}/src"
      pip_requirements = true
      patterns         = ["!\\.terragrunt-source-manifest"]
    }
  ]

  environment_variables = {
    LOG_LEVEL                    = var.log_level
    DRY_RUN                      = var.dry_run
    SES_SMTP_ENDPOINT            = var.ses_smtp_endpoint
    NOTIFICATION_SENDER_EMAIL    = var.notification_sender_email
    NOTIFICATION_RECIPIENT_EMAIL = var.notification_recipient_email
    SECRETS_MANAGER_ENDPOINT     = var.secrets_manager_endpoint
    SMTP_IAM_USERNAME            = var.smtp_iam_username
    SSM_ROTATION_DOCUMENT_NAME   = var.ssm_rotation_document_name
    # SSM_COMMANDS_LIST            = jsonencode(var.ssm_commands_list)
    SSM_COMMANDS_LIST_PARAMETER_NAME = local.ssm_commands_list_parameter_name
    SSM_ROTATE_ON_EC2_INSTANCE_ID    = var.ssm_rotate_on_ec2_instance_id
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "AccessSecrets"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]

    resources = [
      "*"
    ]
  }

  statement {
    sid = "AllowIAMAccessKey"

    actions = [
      "iam:CreateAccessKey",
      "iam:DeleteAccessKey",
      "iam:GetUser",
      "iam:ListAccessKeys",
      "iam:UpdateAccessKey"
    ]

    resources = [
      "arn:${data.aws_partition.current.partition}:iam::*:user/${var.smtp_iam_username}"
    ]
  }

  dynamic "statement" {
    for_each = var.ssm_rotate_on_ec2_instance_id != "" ? [1] : []

    content {
      sid = "AllowSSMSendCommand"

      actions = [
        "ssm:SendCommand"
      ]

      resources = [
        "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}::document/${var.ssm_rotation_document_name}",
        "arn:${data.aws_partition.current.partition}:ec2:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:instance/${var.ssm_rotate_on_ec2_instance_id}",
      ]
    }
  }

    dynamic "statement" {
    for_each = var.create_ssm_parameter != false ? [1] : []

    content {
      sid = "AllowSSMGetParameter"

      actions = [
        "ssm:GetParameter"
      ]

      resources = [
        "arn:${data.aws_partition.current.partition}:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${local.ssm_commands_list_parameter_name}"]
    }
  }
}

locals {
  ssm_commands_list_parameter_name = var.ssm_commands_list_parameter_name != "" ? var.ssm_commands_list_parameter_name : "/lambda/${var.project_name}/ssm_commands_list"
}

resource "aws_lambda_permission" "secretmanager" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.lambda_function_name
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_ssm_parameter" "commands_list" {
  count       = var.create_ssm_parameter ? 1 : 0
  name        = local.ssm_commands_list_parameter_name
  description = "List of commands to run against ec2 instance id to rotate the secret within the application"
  type        = "StringList"
  value       = join(",", var.ssm_commands_list)

  tags = var.tags
}

##############################
# Common
##############################
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
