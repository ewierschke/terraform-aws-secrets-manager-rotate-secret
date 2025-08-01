# terraform-aws-secrets-manager-rotate-ses-secret

A Terraform module to enable IAM user SES SMTP credential rotation via Lambda initiated by 
AWS Secrets Manager.

This Lambda function (supporting resources are created by this module) would be configured as the 
rotation function for a given Secrets Manager secret configured for automatic rotation.
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
expects an executable script to exist within /usr/local/bin/rotate_smtp.sh that will be passed the 
secret arn so that instance adjustments can be made and rollback of failed rotations possible.  As 
secret values should try to remain masked and local to use, this approach seemed safest.

Summary of the four steps in the function:
createSecret - will create a new iam access key pair (deleting old after minor colission avoidance 
and validation) and calculate the SMTP password before storing in the secrets' AWSPENDING label/stage. 
setSecret - attempts to trigger the rotate_smtp.sh script which needs to query the provided secret 
arn for the AWSPENDING label/stage on the target ec2 instance id via SSM run_command and check for
successful execution.
testSecret - Once a sucessful setSecret completes, if set, will attempt to use the new IAM 
credentials to send a test email
finishSecret - If all prior steps succeed, moves the AWSCURRENT label/stage onto the AWSPENDING 
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
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.3 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 4.9 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 4.9 |

## Resources

| Name | Type |
|------|------|
| [tbd]

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| tbd]

## Outputs

No outputs.

<!-- END TFDOCS -->
