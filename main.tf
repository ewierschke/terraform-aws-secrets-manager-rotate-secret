##############################
# Lambda
##############################
module "lambda" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v7.20.1"

  function_name = "${var.project_name}-rotate-ses-smtp-pass-secret"

  description = "Secrets Manager Rotate by Lambda SES SMTP password"
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
    LOG_LEVEL                  = var.log_level
    # ASSUME_ROLE_NAME           = var.assume_role_name
    DRY_RUN                    = var.dry_run
    MAX_WORKERS                = var.max_workers
    AWS_STS_REGIONAL_ENDPOINTS = var.aws_sts_regional_endpoints
    #add SSM Document, iam user name?, 
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "AllowAssumeRole"

    actions = [
      "secretsmanager:GetRandomPassword",
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage"
    ]

    resources = [
      "*"
    ]
  }
}

resource "aws_lambda_permission" "events" {
  for_each = aws_cloudwatch_event_rule.this

  action        = "lambda:InvokeFunction"
  function_name = module.lambda.lambda_function_name
  principal     = "events.amazonaws.com"
  source_arn    = each.value.arn
}

##############################
# Common
##############################
data "aws_partition" "current" {}
