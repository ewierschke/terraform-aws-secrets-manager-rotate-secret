locals {
  lambda_name = "${var.project_name}-rotate-secret-ses-smtp-credentials"
  list_of_subnets_to_attach_lambda = (
    length(var.attach_to_vpc_explicit_list_of_subnet_ids) > 0 ? var.attach_to_vpc_explicit_list_of_subnet_ids :
    (var.attach_to_vpc_id != "" ? data.aws_subnets.private_subnets[0].ids : [])
  )
}

##############################
# Lambda
##############################
module "lambda" {
  #pinning to v7.14.0 to support aws provider v5.74
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v7.14.0"

  function_name = local.lambda_name

  description = "Secrets Manager Initiated rotation by Lamda Function of SES SMTP credentials-${var.project_name}"
  handler     = "secrets_manager_rotation_by_lambda_ses_smtp_credentials.lambda_handler"
  tags        = var.tags

  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda.json

  artifacts_dir                     = var.lambda.artifacts_dir
  build_in_docker                   = var.lambda.build_in_docker
  cloudwatch_logs_retention_in_days = var.lambda.cloudwatch_logs_retention_in_days
  create_package                    = var.lambda.create_package
  ephemeral_storage_size            = var.lambda.ephemeral_storage_size
  ignore_source_code_hash           = var.lambda.ignore_source_code_hash
  local_existing_package            = var.lambda.local_existing_package
  logging_log_group                 = var.lambda.logging_log_group
  memory_size                       = var.lambda.memory_size
  recreate_missing_package          = var.lambda.recreate_missing_package
  runtime                           = var.lambda.runtime
  s3_bucket                         = var.lambda.s3_bucket
  s3_existing_package               = var.lambda.s3_existing_package
  s3_prefix                         = var.lambda.s3_prefix
  store_on_s3                       = var.lambda.store_on_s3
  timeout                           = var.lambda.timeout
  tracing_mode                      = var.lambda.tracing_mode
  use_existing_cloudwatch_log_group = var.lambda.use_existing_cloudwatch_log_group

  #conditionally set if local.list_of_subnets_to_attach_lambda evaluates larger than 0; subnet ids found w name *private* or explicitly list is provided
  vpc_subnet_ids         = length(local.list_of_subnets_to_attach_lambda) > 0 ? local.list_of_subnets_to_attach_lambda : null
  vpc_security_group_ids = length(local.list_of_subnets_to_attach_lambda) > 0 ? [aws_security_group.lambda[0].id] : null
  attach_network_policy  = length(local.list_of_subnets_to_attach_lambda) > 0 ? true : false

  source_path = [
    {
      path             = "${path.module}/src"
      pip_requirements = true
      patterns         = ["!\\.terragrunt-source-manifest"]
    }
  ]

  environment_variables = {
    LOG_LEVEL                     = var.log_level
    DRY_RUN                       = var.dry_run
    SES_SMTP_ENDPOINT             = var.ses_smtp_endpoint
    NOTIFICATION_SENDER_EMAIL     = var.notification_sender_email
    NOTIFICATION_RECIPIENT_EMAIL  = var.notification_recipient_email
    SMTP_IAM_USERNAME             = var.smtp_iam_username
    SSM_ROTATION_DOCUMENT_NAME    = var.ssm_rotation_document_name
    SSM_ROTATE_ON_EC2_INSTANCE_ID = var.ssm_rotate_on_ec2_instance_id
    SNS_TOPIC_ARN                 = aws_sns_topic.rotation_notifications.arn
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "AccessSecret"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]

    resources = [
      "${var.secret_arn_for_lambda_policy}"
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
      "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/${var.smtp_iam_username}"
    ]
  }

  statement {
    sid = "AllowSNSPublish"

    actions = [
      "sns:Publish"
    ]

    resources = [
      "${aws_sns_topic.rotation_notifications.arn}"
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
    for_each = var.ssm_rotate_on_ec2_instance_id != "" ? [1] : []

    content {
      sid = "AllowSSMListCommandInvocations"

      actions = [
        "ssm:ListCommandInvocations"
      ]

      resources = [
        "*"
      ]

      ##not working-unsure how to provide most narrow perms... maybe switch how script gets stdout?
      # condition {
      #   test     = "StringEquals"
      #   variable = "ssm:InstanceId"
      #   values   = ["${var.ssm_rotate_on_ec2_instance_id}"]
      # }
    }
  }
}

resource "aws_lambda_permission" "secretmanager" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.lambda_function_name
  principal     = "secretsmanager.amazonaws.com"
}

resource "aws_sns_topic" "rotation_notifications" {
  name              = "${local.lambda_name}-notifications"
  kms_master_key_id = var.sns_kms_master_key_id
}

resource "aws_sns_topic_subscription" "email_subscription" {
  # Create the subscription only if var.notification_recipient_email is not ""
  count = var.notification_recipient_email != "" ? 1 : 0

  topic_arn = aws_sns_topic.rotation_notifications.arn
  protocol  = "email"
  endpoint  = var.notification_recipient_email
}

data "aws_vpc" "attach_to_vpc" {
  count = var.attach_to_vpc_id != "" ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [var.attach_to_vpc_id]
  }
}

data "aws_subnets" "private_subnets" {
  count = var.attach_to_vpc_id != "" ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.attach_to_vpc[0].id]
  }
  filter {
    name   = "tag:Name"
    values = ["*private*"] # Filters for subnets where the Name tag contains "private"
  }
}

resource "aws_security_group" "lambda" {
  count = length(local.list_of_subnets_to_attach_lambda) > 0 ? 1 : 0

  name        = "${local.lambda_name}-sg"
  description = "${local.lambda_name}-security-group"
  vpc_id      = data.aws_vpc.attach_to_vpc[0].id
}

#this lambda will only be triggered by Secrets Manager, so we only allow all outbound traffic
resource "aws_vpc_security_group_egress_rule" "allow_all_outbound" {
  count = length(local.list_of_subnets_to_attach_lambda) > 0 ? 1 : 0

  security_group_id = aws_security_group.lambda[0].id
  from_port         = 0
  to_port           = 0
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Allow all outbound traffic"
}

##############################
# Common
##############################
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
