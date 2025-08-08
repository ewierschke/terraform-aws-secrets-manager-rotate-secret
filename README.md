# terraform-aws-secrets-manager-rotation-by-lambda-ses-smtp-credentials

A Terraform module creating an AWS Lambda function to enable IAM user SES SMTP credential rotation
initiated by AWS Secrets Manager.

This Lambda function (supporting resources are created by this module) would be configured as the 
rotation function for a given Secrets Manager secret configured for automatic rotation.

*Note - Initial/immediate rotation is performed as soon as the chosen Secret's Rotation
configuration is set to Enabled for automatic rotation in Secrets Manager 
(or when the resource aws_secretsmanager_secret_rotation is applied to the secret)

## Secret Structure

The AWS Secrets Manager secret is expected to contain the following JSON text strings with key-value
pairs structure to ensure proper validation prior to rotation:
```
{
    "iam_user_arn": "<must be pre-populated with iam user arn>", 
    "AccessKeyId": "<to be populated by function>", 
    "SMTPPassword": "<to be popualted by function>", 
    "username": "<must be pre-populated with iam username matching module variable smtp_iam_username to be rotated>"
    "destination_service": "<friendly name of service using this secret; used for set_service current v pending validation>
}
```

## AWS Lambda Function

AWS Lambda Function environment variables are populated based on Terraform variable values in this
module.

The function assumes when calculating the SMTP password that it is executing in the same region as
the intended SES SMTP endpoint for use.

The function follows structure from the Secrets Manager Rotation template and expects four steps.
If chosing to rotate the function on an EC2 instance via SSM, the function expects the target EC2
instance to be reachable via SSM for run_command execution, and expects an executable script to 
preexist within `/usr/local/bin/rotate_smtp.sh` which must accept the secret arn as a script
parameter so that instance adjustments can be made locally on the EC2 and rollback of failed
rotations possible given each scripts logic.  Secret values should remain masked and attempts
should be made to limit exposure in AWS logs.

### Summary of the four steps in the function:
- createSecret - will create a new iam access key pair (deleting old after minor collission
avoidance and validation) and calculate the SES SMTP password before storing in the secrets'
AWSPENDING label/stage. 
- setSecret - attempts to trigger the rotate_smtp.sh script which needs to query the provided secret 
arn for the AWSPENDING label/stage on the target ec2 instance id via SSM run_command and check for
successful execution.
- testSecret - Once a sucessful setSecret completes, if set, will attempt to use the new IAM 
credentials to send a test email
- finishSecret - If all prior steps succeed, moves the AWSCURRENT label/stage onto the AWSPENDING 
label/stage in order for future builds/rotations to retrieve the proper value.

It is assumed that the `rotate_smtp.sh` script will contain logic to ensure the running application
continues to consume functional SMTP credentials and in the event of a failed local execution can
revert to previously functional credentials (ie AWSCURRENT values).

*An example script `rotate_smtp-example.sh` is contained in this repo to show a very simplistic 
approach.  The function assumes the script will exist within /usr/local/bin/rotate_smtp.sh on target
ec2 instance.  Again, this is to avoid passing sensitive values through SSM send_command and
requires ec2 instance to query for AWSPENDING label/stage of secret and script must succeed or
return specific value for success if set_secret

*Note - SSM send_command requires that the target ec2 instance provided has an associated instance
profile which contains permissions to GetSecretValue against the secret arn that triggered the
rotation.

*Note - Ensure that any SCPs limiting iam:CreateAccessKey etc are updated to allow this modules'
Lambda execution role required access to function.

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.74 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.74 |

## Resources

| Name | Type |
|------|------|
| [aws_lambda_permission.secretmanager](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lambda_permission) | resource |
| [aws_sns_topic.rotation_notifications](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic) | resource |
| [aws_sns_topic_subscription.email_subscription](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/sns_topic_subscription) | resource |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name to prefix resources with | `string` | n/a | yes |
| <a name="input_secret_arn_for_lambda_policy"></a> [secret\_arn\_for\_lambda\_policy](#input\_secret\_arn\_for\_lambda\_policy) | ARN of the secret to be configured for rotation, this is used to allow the lambda function to access only this secret | `string` | n/a | yes |
| <a name="input_ses_smtp_endpoint"></a> [ses\_smtp\_endpoint](#input\_ses\_smtp\_endpoint) | SES SMTP Endpoint to test new smtp credentials against | `string` | n/a | yes |
| <a name="input_smtp_iam_username"></a> [smtp\_iam\_username](#input\_smtp\_iam\_username) | IAM Username for which to generate new SES SMTP credentials | `string` | n/a | yes |
| <a name="input_dry_run"></a> [dry\_run](#input\_dry\_run) | Boolean toggle to control the dry-run mode of the lambda function | `bool` | `true` | no |
| <a name="input_lambda"></a> [lambda](#input\_lambda) | Object of optional attributes passed on to the lambda module | <pre>object({<br/>    artifacts_dir                     = optional(string, "builds")<br/>    build_in_docker                   = optional(bool, false)<br/>    cloudwatch_logs_retention_in_days = optional(number, 365)<br/>    create_package                    = optional(bool, true)<br/>    ephemeral_storage_size            = optional(number)<br/>    ignore_source_code_hash           = optional(bool, true)<br/>    local_existing_package            = optional(string)<br/>    logging_log_group                 = optional(string, null)<br/>    memory_size                       = optional(number, 128)<br/>    recreate_missing_package          = optional(bool, false)<br/>    runtime                           = optional(string, "python3.12")<br/>    s3_bucket                         = optional(string)<br/>    s3_existing_package               = optional(map(string))<br/>    s3_prefix                         = optional(string)<br/>    store_on_s3                       = optional(bool, false)<br/>    timeout                           = optional(number, 300)<br/>    tracing_mode                      = optional(string, "PassThrough")<br/>    use_existing_cloudwatch_log_group = optional(bool, false)<br/>  })</pre> | `{}` | no |
| <a name="input_log_level"></a> [log\_level](#input\_log\_level) | Log level for lambda | `string` | `"INFO"` | no |
| <a name="input_notification_recipient_email"></a> [notification\_recipient\_email](#input\_notification\_recipient\_email) | Email address to send notification email to, if empty string provided, will not create SNS subscription | `string` | `""` | no |
| <a name="input_notification_sender_email"></a> [notification\_sender\_email](#input\_notification\_sender\_email) | SES Verified identity/email address used in FROM field of notification email after rotation, if empty string provided, function won't try to send SES notification of rotation using new rotated credentials | `string` | `""` | no |
| <a name="input_sns_kms_master_key_id"></a> [sns\_kms\_master\_key\_id](#input\_sns\_kms\_master\_key\_id) | SNS KMS Master Key ID to use for SNS topic encryption, if not overridden, will use default SNS KMS key | `string` | `"alias/aws/sns"` | no |
| <a name="input_ssm_rotate_on_ec2_instance_id"></a> [ssm\_rotate\_on\_ec2\_instance\_id](#input\_ssm\_rotate\_on\_ec2\_instance\_id) | EC2 instance ID (ie i-xxxxxxxxxxxxxxxxx) on which to execute SSM commands to rotate secret being used, if empty string provided, function won't attempt ssm:SendCommand | `string` | `""` | no |
| <a name="input_ssm_rotation_document_name"></a> [ssm\_rotation\_document\_name](#input\_ssm\_rotation\_document\_name) | SSM Document name (ie AWS-RunShellScript) to use for updating credentials on EC2 instance id provided | `string` | `"AWS-RunShellScript"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags for resource | `map(string)` | `{}` | no |

## Outputs

No outputs.

<!-- END TFDOCS -->
