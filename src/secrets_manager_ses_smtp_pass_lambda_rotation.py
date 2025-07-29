"""Script to handle SMTP credential rotation, triggered by SecretsManager."""
#!/usr/bin/env python3

#ref-template from https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py
#combined w - https://github.com/aws-samples/serverless-mail/blob/main/ses-credential-rotation/ses_credential_rotator/lambda_function.py
#combined w - https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerElasticacheUserRotation/lambda_function.py

import base64
import collections
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hmac
import hashlib
import json
import logging
import os
import smtplib
import time

import boto3
import botocore

# logger = logging.getLogger()
# # Get the log level from the environment variable and default to INFO if not set
# log_level = os.environ.get('LOG_LEVEL', 'INFO')
# log.setLevel(log_level)

# Standard logging config
DEFAULT_LOG_LEVEL = logging.INFO
LOG_LEVELS = collections.defaultdict(
    lambda: DEFAULT_LOG_LEVEL,
    {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
    },
)

# Lambda initializes a root logger that needs to be removed in order to set a
# different logging config
root = logging.getLogger()
if root.handlers:
    for handler in root.handlers:
        root.removeHandler(handler)

logging.basicConfig(
    format="%(asctime)s.%(msecs)03dZ [%(name)s][%(levelname)s]: %(message)s ",
    datefmt="%Y-%m-%dT%H:%M:%S",
    level=LOG_LEVELS[os.environ.get("LOG_LEVEL", "").upper()],
)

log = logging.getLogger(__name__)

SMTP_REGIONS = [
    "us-east-2",  # US East (Ohio)
    "us-east-1",  # US East (N. Virginia)
    "us-west-2",  # US West (Oregon)
    "ap-south-1",  # Asia Pacific (Mumbai)
    "ap-northeast-2",  # Asia Pacific (Seoul)
    "ap-southeast-1",  # Asia Pacific (Singapore)
    "ap-southeast-2",  # Asia Pacific (Sydney)
    "ap-northeast-1",  # Asia Pacific (Tokyo)
    "ca-central-1",  # Canada (Central)
    "eu-central-1",  # Europe (Frankfurt)
    "eu-west-1",  # Europe (Ireland)
    "eu-west-2",  # Europe (London)
    "eu-south-1",  # Europe (Milan)
    "eu-north-1",  # Europe (Stockholm)
    "sa-east-1",  # South America (Sao Paulo)
    "us-gov-west-1",  # AWS GovCloud (US)
    "us-gov-east-1",  # AWS GovCloud (US)
]

REGION = os.environ.get("AWS_REGION")
#TODO-implement dry_run functionality that only logs what would be done but does not change values
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
TEST_STAGE_SES_SMTP_ENDPOINT = os.environ.get("SES_SMTP_ENDPOINT", "email-smtp.us-east-1.amazonaws.com") # Example for us-east-1
TEST_STAGE_SES_SMTP_PORT = 587
TEST_STAGE_EMAIL_SUBJECT = "Test Email from Lambda-"+ os.environ['AWS_LAMBDA_FUNCTION_NAME'] + " via Amazon SES"
TEST_STAGE_EMAIL_BODY_TEXT = "This is a test email sent via Lambda function " + os.environ['AWS_LAMBDA_FUNCTION_NAME'] + " after Secrets Manager triggered secret rotation using new Amazon SES credentials."
TEST_STAGE_EMAIL_BODY_HTML = "<html><body><h1>Hello!</h1><p>This is a <b>test email</b> sent after secret rotation using Lambda/Python and Amazon SES SMTP.</p></body></html>"

# what rotation targets and notification vars
TEST_STAGE_SENDER_EMAIL = os.environ.get("NOTIFICATION_SENDER_EMAIL")
TEST_STAGE_RECIPIENT_EMAIL = os.environ.get("NOTIFICATION_RECIPIENT_EMAIL")
SMTP_IAM_USERNAME = os.environ['SMTP_IAM_USERNAME']
SSM_ROTATION_DOCUMENT_NAME = os.environ['SSM_ROTATION_DOCUMENT_NAME']
SSM_COMMANDS_LIST = os.environ['SSM_COMMANDS_LIST']
SSM_SERVER_TAG = os.environ['SSM_SERVER_TAG']
SSM_SERVER_TAG_VALUE = os.environ['SSM_SERVER_TAG_VALUE']

# These values are required to calculate the signature. Do not change them.
DATE = "11111111"
SERVICE = "ses"
MESSAGE = "SendRawEmail"
TERMINAL = "aws4_request"
VERSION = 0x04


def lambda_handler(event, context):
    """
    Secrets Manager Rotation

    AWS Secrets Manager rotation lambda of IAM user credentials used for SES SMTP sending
    Expects Secret to be json key/value, prepopulated with username and user_arn keys

    Args:
        event (dict): Lambda dictionary of event parameters. These keys must include the following:
            - SecretId: The secret ARN or identifier
            - ClientRequestToken: The ClientRequestToken of the secret version
            - Step: The rotation step (one of createSecret, setSecret, testSecret, or finishSecret)

        context (LambdaContext): The Lambda runtime information

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        ValueError: If the secret is not properly configured for rotation

        KeyError: If the event parameters do not contain the expected keys
    """
    log.info("Lambda function ARN: %s", context.invoked_function_arn)
    log.info("AWS Event: %s", event)

    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    # Setup the client
    service_client = boto3.client('secretsmanager')

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        log.error("Secret %s is not enabled for rotation", arn)
        raise ValueError(f"Secret {arn} is not enabled for rotation")
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        log.error("Secret version %s has no stage for rotation of secret %s.", token, arn)
        raise ValueError(f"Secret version {token} has no stage for rotation of secret {arn}.")
    if "AWSCURRENT" in versions[token]:
        log.info("Secret version %s already set as AWSCURRENT for secret %s.", token, arn)
        return
    elif "AWSPENDING" not in versions[token]:
        log.error("Secret version %s not set as AWSPENDING for rotation of secret %s.", token, arn)
        raise ValueError(f"Secret version {token} not set as AWSPENDING for rotation of secret {arn}.")

    if step == "createSecret":
        log.info("Executing Create Secret Function")
        create_secret(service_client, arn, token, REGION, SMTP_IAM_USERNAME)
    elif step == "setSecret":
        log.info("Executing Set Secret Function")
        set_secret(service_client, arn, token, SSM_ROTATION_DOCUMENT_NAME, SSM_COMMANDS_LIST, SSM_SERVER_TAG, SSM_SERVER_TAG_VALUE)
    elif step == "testSecret":
        log.info("Executing Test Secret Function")
        #TODO - decide about adding more params... need to provide option to send email or just continue
        test_secret(service_client, arn, token, TEST_STAGE_SES_SMTP_ENDPOINT)
    elif step == "finishSecret":
        log.info("Executing Finish Secret Function")
        finish_secret(service_client, arn, token)
    else:
        log.error("lambda_handler: Invalid step parameter %s for secret %s", step, arn)
        raise ValueError(f"Invalid step parameter {step} for secret {arn}")


def create_secret(service_client, arn, token, region, smtp_iam_username):
    """
    Create the secret

    This method first checks for the existence of a secret for the passed in token. If one does not exist, it will generate a
    new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Make sure the current secret exists
    current_secret = _get_secret_dict(service_client, arn, "AWSCURRENT")

    # Verify if the username stored in environment variable is the same with the one stored in current_secret
    _verify_user_name(current_secret)

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        log.info("createSecret: Successfully retrieved secret for %s.", arn)
    except service_client.exceptions.ResourceNotFoundException:
        log.info("createSecret: No AWSPENDING label exists, create new for %s.", arn)
        #Generate an SMTP password

        # Create new Access key and secret key
        iam_client = boto3.client('iam')

        smtp_iam_user_arn = _get_iam_user_arn(iam_client, smtp_iam_username)

        keys_response = iam_client.list_access_keys(UserName=smtp_iam_username)
        access_keys = sorted(keys_response['AccessKeyMetadata'], key=lambda x: x['CreateDate'])

        #IAM user can have 2 keys, delete the oldest before creating a new one
        #TODO-or should the old key only be set to inactive (in finish_secret step to ensure old still works until new is successfully set in instance id) in case it is still needed(ie revert?), 
        #first try to del inactive then oldest?
        if len(access_keys) >= 2:
            oldest_key_id = access_keys[0]['AccessKeyId']
            iam_client.delete_access_key(UserName=smtp_iam_username, AccessKeyId=oldest_key_id)
            log.info("Deleted oldest access key for %s: %s", smtp_iam_username, oldest_key_id)

        new_key = iam_client.create_access_key(
            UserName=smtp_iam_username
        )
        new_access_key = new_key['AccessKey']['AccessKeyId']
        new_secret_key = new_key['AccessKey']['SecretAccessKey']

        new_smtp_secret = _calculate_key(new_secret_key, region)
        #some secret dict structure validation, expects json w four keys;
        #user_arn (must be pre-populated, updated to show which AKID belongs), username (must match lambda func env var), AccessKeyId, SMTPPassword
        new_secret = _get_secret_dict(service_client, arn, "AWSCURRENT")
        new_secret['user_arn'] = smtp_iam_user_arn
        new_secret['AccessKeyId'] = new_access_key
        new_secret['SMTPPassword'] = new_smtp_secret

        # Put the secret
        try:
            service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=json.dumps(new_secret), VersionStages=['AWSPENDING'])
        except botocore.exceptions.ClientError as error:
            log.error(error)
            #TODO-maybe this should just mark inactive, and next go-round would check for inactive to del before oldest akid?
            log.error("createSecret: Put secret failed, removing IAM key from user")
            iam_client.delete_access_key(
                UserName=smtp_iam_username,
                AccessKeyId=new_access_key
            )
            log.error("createSecret: Secret couldn't be updated, removing IAM key pair")
            raise error

        log.info("createSecret: Successfully put secret for ARN %s and version %s.", arn, token)


##TODO-in tf, how would perms be granted to tagged instances?
def set_secret(service_client, arn, token, ssm_document_name, ssm_commands_list, ssm_server_tag, ssm_server_tag_value):
    """
    Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version
    """
    # This is where the secret should be set in the service
    # Make sure the current secret exists
    _get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_secret = _get_secret_dict(service_client, arn, "AWSPENDING", token)

    # Verify if the username stored in environment variable is the same with the one stored in pending_secret
    _verify_user_name(pending_secret)

    # secret_string = pending_secret['SecretString']
    secret_username = pending_secret['AccessKeyId']
    secret_password = pending_secret['SMTPPassword']

    # If SSM Document name provided, Execute the SSM command against the tagged servers with the new secret
    #TODO-test w commands
    if not ssm_document_name == "":
        log.info("setSecret: ssm_document_name provided, attempting SSM Run Command")
        ssm_client = boto3.client('ssm')
        #TODO-update params passed
        command_id = _execute_ssm_run_command(ssm_client, ssm_document_name, ssm_commands_list, ssm_server_tag, ssm_server_tag_value, secret_username, secret_password)

        # Wait for invocations to appear for the command
        _wait_for_ssm_invocations(ssm_client, command_id)

        # Check all complete successfully
        _check_invocation_success(ssm_client, command_id)
    else:
        log.info("setSecret: ssm_document_name NOT provided, no SSM actions, continue...")

    #TODO-add dest host in output (or key/val of tags?)
    log.info("setSecret: Successfully set secret for %s.", arn)


def test_secret(service_client, arn, token, ses_smtp_endpoint):
    """
    Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret belongs to. For example, if the secret
    is a database credential, this method should validate that the user can login with the password in AWSPENDING and that the user has
    all of the expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version
    """
    # This is where the secret should be tested against the service
    # Get the pending secret
    # pending_secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")['SecretString']
    pending_secret = _get_secret_dict(service_client, arn, "AWSPENDING", token)

    # Verify if the username stored in environment variable is the same with the one stored in pending_secret
    _verify_user_name(pending_secret)

    secret_username = pending_secret['AccessKeyId']
    secret_password = pending_secret['SMTPPassword']

    if not TEST_STAGE_SENDER_EMAIL == "":
        # Create a new smtp client
        smtp_client = smtplib.SMTP_SSL(ses_smtp_endpoint)

        # Re-try login attempts to give the new credential time to stabilise
        login_retry = 15
        successful = False

        # Loop with a delay to give the time for a credential to activate
        while login_retry != 0 and not successful:

            # Try a login to the server
            try:
                smtp_login = smtp_client.login(secret_username, secret_password)
            except smtplib.SMTPAuthenticationError as e:
                #guessing at error being raised to satisfy linter-revisit
                log.info("error: %s: login unsuccessful: %s", e, login_retry)
                time.sleep(1)
                login_retry -= 1
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.info("error: %s: login unsuccessful: %s", e, login_retry)
                time.sleep(1)
                login_retry -= 1
            else:
                if smtp_login[0] == 235:
                    successful = True

        if not successful:
            raise RuntimeError(f"Unable to login to smtp server : {smtp_login}")

        #TODO-revisit vars to pass
        _send_ses_email(
          ses_smtp_endpoint, TEST_STAGE_SES_SMTP_PORT, secret_username, secret_password,
           TEST_STAGE_SENDER_EMAIL, TEST_STAGE_RECIPIENT_EMAIL, TEST_STAGE_EMAIL_SUBJECT, 
           TEST_STAGE_EMAIL_BODY_TEXT, TEST_STAGE_EMAIL_BODY_HTML
        )
    else:
        log.info("testSecret: TEST_STAGE_SENDER_EMAIL NOT provided, continue...")


def finish_secret(service_client, arn, token):
    """
    Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the AWSCURRENT secret.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn does not exist
    """
    # First describe the secret to get the current version
    metadata = service_client.describe_secret(SecretId=arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                log.info("finishSecret: Version %s already marked as AWSCURRENT for %s", version, arn)
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    log.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s.", token, arn)


def _sign(key, msg):
    """HMAC sign"""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def _calculate_key(secret_access_key, region):
    """Calculate key for SMTP credentials"""
    if region not in SMTP_REGIONS:
        raise ValueError(f"The {region} Region doesn't have an SMTP endpoint.")

    signature = _sign(("AWS4" + secret_access_key).encode('utf-8'), DATE)
    signature = _sign(signature, region)
    signature = _sign(signature, SERVICE)
    signature = _sign(signature, TERMINAL)
    signature = _sign(signature, MESSAGE)
    signature_and_version = bytes([VERSION]) + signature
    smtp_password = base64.b64encode(signature_and_version)
    return smtp_password.decode('utf-8')


def _execute_ssm_run_command(ssm_client, document_name, ssm_commands_list, server_key, server_key_value, secret_username, secret_password):
    # Execute the provided SSM document to update and restart the email server

    log.info("_execute_ssm_run_command: SSM Commands list to execute %s.", ssm_commands_list)

    response = ssm_client.send_command(
      Targets=[
          {
              'Key': f"tag:{server_key}",
              'Values': [
                  server_key_value,
              ]
          },
      ],
      DocumentName=document_name,
      CloudWatchOutputConfig={
          'CloudWatchOutputEnabled': True
      },
      #need to change parameters to take commands list
      Parameters={
        'SESUsername': [
          secret_username,
        ],
        'SESPassword': [
          secret_password
        ]
      },
    )

    command_id = response['Command']['CommandId']
    log.info("finishSecret: SSM Command ID %s executed.", command_id)
    return command_id


def _wait_for_ssm_invocations(ssm_client, command_id):
    # list_command_invocations starts with returning 0 invocations and gradually adds them hence this logic
    invocations_found = False
    retry = 10

    while not invocations_found and retry > 0:

        if len(ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']) > 0:
            invocations_found = True
        else:
            time.sleep(0.5)
            retry -= 1

    if not invocations_found:
        raise RuntimeError("SSM Document was not invoked on any instances, check the tags are set correctly")


def _check_invocation_success(ssm_client, command_id):
    # Check all invocations complete, raise an error for those not successful
    invocations_complete = False
    while not invocations_complete:

        complete_invocations = 0

        command_invocation_status = ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']
        for invocation in command_invocation_status:

            log.info("finishSecret: Status of SSM Run Command on instance %s is %s", invocation['InstanceId'], invocation['Status'])
            if invocation['Status'] != 'Pending' and invocation['Status'] != 'InProgress':
                complete_invocations += 1

            # List isn't complete at first execution, this catches it growing
            total_invocations = len(ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations'])

        if complete_invocations == total_invocations:
            invocations_complete = True
        else:
            time.sleep(5)

    # Raise an error if any were not successful
    command_invocation_status = ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']
    invocation_errors = ""
    for invocation in command_invocation_status:
        if invocation['Status'] != 'Success':
            invocation_errors += f"SSM Invocation on host {invocation['InstanceId']}  {invocation['Status']}\n"

    if invocation_errors:
        raise RuntimeError(invocation_errors)


def _get_secret_dict(secrets_manager_service_client, secret_arn, stage, token=None):
    """
    Gets the secret dictionary corresponding for the secret secret_arn, stage, and token
    This helper function gets credentials for the arn and stage passed in and returns the dictionary by parsing the JSON string

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        KeyError: If the secret has no user_arn
    """
    # Only do VersionId validation against the stage if a token is passed in
    if token is None:
        secret = secrets_manager_service_client.get_secret_value(SecretId=secret_arn, VersionStage=stage)
    else:
        secret = secrets_manager_service_client.get_secret_value(SecretId=secret_arn, VersionId=token, VersionStage=stage)
    plaintext = secret['SecretString']
    try:
        secret_dict = json.loads(plaintext)
    except Exception as exc:
        # wrapping json parser exceptions to avoid possible password disclosure
        log.error("Invalid secret value json for secret %s.", secret_arn)
        raise ValueError(f"Invalid secret value json for secret {secret_arn}.") from exc

    # Validates if there is a user associated to the secret
    if "user_arn" not in secret_dict:
        log.error("createSecret: secret %s has no user_arn defined.", secret_arn)
        raise KeyError(f"createSecret: secret {secret_arn} has no user_arn defined.")

    return secret_dict


def _verify_user_name(secret):
    """
    Verify whether SMTP_IAM_USERNAME set in Lambda environment variable matches what's set in the secret

    Args:
        secret: The secret from Secrets Manager
    
    Raises:
        verificationException: username in Lambda environment variable doesn't match the one stored in the secret
    """
    env_iam_smtp_user_name = os.environ['SMTP_IAM_USERNAME']
    secret_user_name = secret["username"]
    if env_iam_smtp_user_name != secret_user_name:
        log.error("User %s is not allowed to use this Lambda function for rotation", secret_user_name)
        raise ValueError(f"User {secret_user_name} is not allowed to use this Lambda function for rotation")


#TODO-test
def _send_ses_email(smtp_host, smtp_port, smtp_username, smtp_password,
                   sender_email, recipient_email, subject, body_text, body_html=None):
    """
    Sends an email using Amazon SES SMTP credentials.

    Args:
        smtp_host (str): The Amazon SES SMTP endpoint (e.g., 'email-smtp.us-east-1.amazonaws.com').
        
        smtp_port (int): The SMTP port (e.g., 587 for TLS).
        
        smtp_username (str): Your Amazon SES SMTP username (Access Key ID).
        
        smtp_password (str): Your Amazon SES SMTP password (Secret Access Key converted to an SMTP password).
        
        sender_email (str): The verified sender email address in Amazon SES.
        
        recipient_email (str): The recipient email address.
        
        subject (str): The subject of the email.
        
        body_text (str): The plain text content of the email.
        
        body_html (str, optional): The HTML content of the email. Defaults to None.
    """
    try:
        # Create a multipart message if HTML body is provided, otherwise a plain text message
        if body_html:
            msg = MIMEMultipart("alternative")
            part1 = MIMEText(body_text, "plain")
            part2 = MIMEText(body_html, "html")
            msg.attach(part1)
            msg.attach(part2)
        else:
            msg = MIMEText(body_text, "plain")

        msg["Subject"] = subject
        msg["From"] = sender_email
        msg["To"] = recipient_email

        # Connect to the SES SMTP server
        server = smtplib.SMTP(smtp_host, smtp_port)
        server.ehlo()  # Identify yourself to the SMTP server
        server.starttls()  # Start TLS encryption
        server.ehlo()  # Re-identify after starting TLS

        # Log in to the SMTP server
        server.login(smtp_username, smtp_password)

        # Send the email
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.close()
        log.info("Email sent successfully!")

    except Exception as e:
        raise RuntimeError(f"Error sending email: {e}") from e


def _get_iam_user_arn(iam_service_client, username):
    """
    Retrieves the ARN of a specified IAM user.

    Args:
        iam_service_client (client): The iam service client

        username (str): The name of the IAM user.

    Returns:
        str: The ARN of the IAM user, or None if the user is not found.
    """
    try:
        response = iam_service_client.get_user(UserName=username)
        user_arn = response['User']['Arn']
        return user_arn
    except iam_service_client.exceptions.NoSuchEntityException:
        print(f"IAM user '{username}' not found.")
        return None
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"An error occurred: {e}")
        return None
