# terraform-aws-secrets-manager-rotate-ses-secret

A Terraform module to enable IAM user SES SMTP credential rotation via Lambda initiated by 
AWS Secrets Manager.

This Lambda function (supporting resources are created by this module) would be configured as the 
rotation function for a given Secrets Manager secret configured for automatic rotation.

*Note - Initial/immediate rotation is performed as soon as the secrets Rotation configuration is set
to Enabled for automatic rotation in Secrets Manager

The secret is expected to contain the following key/value structure to ensure proper validation 
prior to rotation:
{
    "iam_user_arn": "<to be populated by function>", 
    "AccessKeyId": "<to be populated by function>", 
    "SMTPPassword": "<to be popualted by function>", 
    "username": "<must be pre-populated with iam username matching module variable smtp_iam_username to be rotated>"
}

Function environment variables are populated based on variable values in this module.

The function follows structure from the Secrets Manager Rotation template and expects four steps.
The function expects the target EC2 instance to be reachable via SSM for run_command execution, and 
expects an executable script to exist within `/usr/local/bin/rotate_smtp.sh` that will accecpt the 
secret arn so that instance adjustments can be made and rollback of failed rotations possible.  As 
secret values should try to remain masked and local to use, this approach seemed safest.

Summary of the four steps in the function:
- createSecret - will create a new iam access key pair (deleting old after minor colission avoidance 
and validation) and calculate the SMTP password before storing in the secrets' AWSPENDING label/stage. 
- setSecret - attempts to trigger the rotate_smtp.sh script which needs to query the provided secret 
arn for the AWSPENDING label/stage on the target ec2 instance id via SSM run_command and check for
successful execution.
- testSecret - Once a sucessful setSecret completes, if set, will attempt to use the new IAM 
credentials to send a test email
- finishSecret - If all prior steps succeed, moves the AWSCURRENT label/stage onto the AWSPENDING 
label/stage in order for future builds/rotations to retrieve the proper value.

It is assumed that the rotate_smtp.sh script will contain logic to ensure the running application
continues to consume functional SMTP credentials and in the event of a failed local execution can
revert to previously functional credentials (ie AWSCURRENT values).

*An example script rotate_smtp-example.sh is contained in this repo to show a very simplistic 
approach.  The function assumes the script will exist within /usr/local/bin/rotate_smtp.sh on target
ec2 instance.  Again, this is to avoid passing sensitive values through SSM send_command and
requires ec2 instance to query for AWSPENDING label/stage of secret and script must succeed or
return specific value for success if set_secret

*Note - this requires that target ec2 instance has an associated instance profile whic contains
permissions to GetSecretValue against the secret that triggered the rotation.

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.74 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | 6.7.0 |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name to prefix resources with | `string` | n/a | yes |
| <a name="input_ses_smtp_endpoint"></a> [ses\_smtp\_endpoint](#input\_ses\_smtp\_endpoint) | SES SMTP Endpoint to test new smtp credentials against | `string` | n/a | yes |
| <a name="input_smtp_iam_username"></a> [smtp\_iam\_username](#input\_smtp\_iam\_username) | IAM Username for which to generate new SES SMTP credentials | `string` | n/a | yes |
| <a name="input_dry_run"></a> [dry\_run](#input\_dry\_run) | Boolean toggle to control the dry-run mode of the lambda function | `bool` | `true` | no |
| <a name="input_lambda"></a> [lambda](#input\_lambda) | Object of optional attributes passed on to the lambda module | <pre>object({<br/>    artifacts_dir            = optional(string, "builds")<br/>    build_in_docker          = optional(bool, false)<br/>    create_package           = optional(bool, true)<br/>    ephemeral_storage_size   = optional(number)<br/>    ignore_source_code_hash  = optional(bool, true)<br/>    local_existing_package   = optional(string)<br/>    memory_size              = optional(number, 128)<br/>    recreate_missing_package = optional(bool, false)<br/>    runtime                  = optional(string, "python3.12")<br/>    s3_bucket                = optional(string)<br/>    s3_existing_package      = optional(map(string))<br/>    s3_prefix                = optional(string)<br/>    store_on_s3              = optional(bool, false)<br/>    timeout                  = optional(number, 300)<br/>  })</pre> | `{}` | no |
| <a name="input_log_level"></a> [log\_level](#input\_log\_level) | Log level for lambda | `string` | `"INFO"` | no |
| <a name="input_notification_recipient_email"></a> [notification\_recipient\_email](#input\_notification\_recipient\_email) | Email address to send notification email to, if unset will not create SNS subscription | `string` | `""` | no |
| <a name="input_notification_sender_email"></a> [notification\_sender\_email](#input\_notification\_sender\_email) | SES Verified identity/email address used in FROM field of notification email after rotation, if empty string function won't try to send SES notification of rotation using new rotated credentials | `string` | `""` | no |
| <a name="input_ssm_rotate_on_ec2_instance_id"></a> [ssm\_rotate\_on\_ec2\_instance\_id](#input\_ssm\_rotate\_on\_ec2\_instance\_id) | EC2 instance ID (ie i-xxxxxxxxxxxxxxxxx) on which to execute SSM commands to rotate secret being used, if empty string provided, function won't attempt ssm:SendCommand | `string` | `""` | no |
| <a name="input_ssm_rotation_document_name"></a> [ssm\_rotation\_document\_name](#input\_ssm\_rotation\_document\_name) | SSM Document name (ie AWS-RunShellScript) to use with Command List for updating credentials on EC2 instance id provided | `string` | `"AWS-RunShellScript"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags for resource | `map(string)` | `{}` | no |

## Outputs

No outputs.

<!-- END TFDOCS -->
