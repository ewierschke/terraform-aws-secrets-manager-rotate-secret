"""Scripte to handle SMTP credential rotation, triggered by SecretsManager."""
#!/usr/bin/env python3

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#ref-template from https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py
#combined w - https://github.com/aws-samples/serverless-mail/blob/main/ses-credential-rotation/ses_credential_rotator/lambda_function.py


import collections
import logging
import os
import hmac
import hashlib
import base64
import smtplib
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
TEST_STAGE_SES_SMTP_ENDPOINT = os.environ.get("SES_SMTP_ENDPOINT", "email-smtp.us-east-1.amazonaws.com") # Example for us-east-1
TEST_STAGE_SES_SMTP_PORT = 587
TEST_STAGE_SENDER_EMAIL = os.environ.get("NOTIFICATION_SENDER_EMAIL")
TEST_STAGE_RECIPIENT_EMAIL = os.environ.get("NOTIFICATION_RECIPIENT_EMAIL")
TEST_STAGE_EMAIL_SUBJECT = "Test Email from Lambda/Python via SES"
TEST_STAGE_EMAIL_BODY_TEXT = "This is a test email sent after secret rotation using Python and Amazon SES SMTP."
TEST_STAGE_EMAIL_BODY_HTML = "<html><body><h1>Hello!</h1><p>This is a <b>test email</b> sent after secret rotation using Lambda/Python and Amazon SES SMTP.</p></body></html>"

# And the environment input details
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
    """Secrets Manager Rotation Template

    This is a template for creating an AWS Secrets Manager rotation lambda

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
        raise ValueError("Secret %s is not enabled for rotation", arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        log.error("Secret version %s has no stage for rotation of secret %s.", token, arn)
        raise ValueError("Secret version %s has no stage for rotation of secret %s.", token, arn)
    if "AWSCURRENT" in versions[token]:
        log.info("Secret version %s already set as AWSCURRENT for secret %s.", token, arn)
        return
    if "AWSPENDING" not in versions[token]:
        log.error("Secret version %s not set as AWSPENDING for rotation of secret %s.", token, arn)
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s.", token, arn)

    if step == "createSecret":
        log.info("Executing Create Secret Function")
        #TODO - decide about adding more params
        create_secret(service_client, arn, token, REGION, SMTP_IAM_USERNAME)

    elif step == "setSecret":
        log.info("Executing Set Secret Function")
        #TODO - decide about adding more params
        set_secret(service_client, arn, token, SSM_ROTATION_DOCUMENT_NAME, SSM_COMMANDS_LIST, SSM_SERVER_TAG, SSM_SERVER_TAG_VALUE)

    elif step == "testSecret":
        log.info("Executing Test Secret Function")
        #TODO - decide about adding more params... need to provide option to send email or just continue
        test_secret(service_client, arn, token, TEST_STAGE_SES_SMTP_ENDPOINT)

    elif step == "finishSecret":
        log.info("Executing Finish Secret Function")
        #TODO - decide about adding more params
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def sign(key, msg):
    """HMAC sign"""
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def calculate_key(secret_access_key, region):
    """Calculate key for SMTP credentials"""
    if region not in SMTP_REGIONS:
        raise ValueError(f"The {region} Region doesn't have an SMTP endpoint.")

    signature = sign(("AWS4" + secret_access_key).encode('utf-8'), DATE)
    signature = sign(signature, region)
    signature = sign(signature, SERVICE)
    signature = sign(signature, TERMINAL)
    signature = sign(signature, MESSAGE)
    signature_and_version = bytes([VERSION]) + signature
    smtp_password = base64.b64encode(signature_and_version)
    return smtp_password.decode('utf-8')


#TODO - decide about adding more params (where to get smtp_iam_username)
def create_secret(service_client, arn, token, region, smtp_iam_username):
    """Create the secret

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
    service_client.get_secret_value(SecretId=arn, VersionStage="AWSCURRENT")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        log.info("createSecret: Successfully retrieved secret for %s.", arn)
    except service_client.exceptions.ResourceNotFoundException:
        ## Get exclude characters from environment variable
        #exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else '/@"\'\\'
        #REPLACE HERE w SMTP-- Generate a random password
        #passwd = service_client.get_random_password(ExcludeCharacters=exclude_characters)

        # Create new Access key and secret key
        iam_client = boto3.client('iam')

        keys_response = iam_client.list_access_keys(UserName=smtp_iam_username)
        access_keys = sorted(keys_response['AccessKeyMetadata'], key=lambda x: x['CreateDate'])

        #IAM user can have 2 keys, delete the oldest before creating a new one
        #or should the old key only be set to inactive in case it is still needed(ie revert?)
        if len(access_keys) >= 2:
            oldest_key_id = access_keys[0]['AccessKeyId']
            iam_client.delete_access_key(UserName=smtp_iam_username, AccessKeyId=oldest_key_id)
            log.info("Deleted oldest access key for %s: %s", smtp_iam_username, oldest_key_id)

        new_key = iam_client.create_access_key(
            UserName=smtp_iam_username
        )

        new_access_key = new_key['AccessKey']['AccessKeyId']
        new_secret_key = new_key['AccessKey']['SecretAccessKey']

        new_smtp_secret = calculate_key(new_secret_key, region)
        new_secret = f'{new_access_key}:{new_smtp_secret}'

        # Put the secret
        try:
            service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=new_secret, VersionStages=['AWSPENDING'])
        except botocore.exceptions.ClientError as error:

            print(error)
            print("Put secret failed, removing IAM key from user")
            iam_client.delete_access_key(
                UserName=smtp_iam_username,
                AccessKeyId=new_access_key
            )

            raise Exception("Secret couldn't be updated, removing IAM key pair")

        #keep for ref?
        #service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=passwd['RandomPassword'], VersionStages=['AWSPENDING'])
        log.info("createSecret: Successfully put secret for ARN %s and version %s.", arn, token)


##TODO-update params passed - ie based on what execute_ssm needs -- add control of whether to even try ssm?
def set_secret(service_client, arn, token, ssm_document_name, ssm_commands_list, ssm_server_tag, ssm_server_tag_value):
    """Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. For example, if the secret is a database
    credential, this method should take the value of the AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    """
    # This is where the secret should be set in the service
    # Now try to get the secret version, if that fails, put a new secret
    try:
        current_secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        log.info("setSecret: Successfully retrieved secret for %s.", arn)
    except service_client.exceptions.ResourceNotFoundException:
        raise Exception("AWSPENDING secret doesn't exist to set on service")

    secret_string = current_secret["SecretString"]
    secret_username = secret_string.split(":")[0]
    secret_password = secret_string.split(":")[1]

    # Execute the SSM command against the tagged servers with the new secret
    ##TODO-update params passed
    if not ssm_document_name == "":
        log.info("setSecret: ssm_document_name provided, attempting SSM Run Command")
        ssm_client = boto3.client('ssm')
        command_id = _execute_ssm_run_command(ssm_client, ssm_document_name, ssm_commands_list, ssm_server_tag, ssm_server_tag_value, secret_username, secret_password)

        # Wait for invocations to appear for the command
        _wait_for_ssm_invocations(ssm_client, command_id)

        # Check all complete successfully
        _check_invocation_success(ssm_client, command_id)
    else:
        log.info("setSecret: ssm_document_name NOT provided, continue...")

    ##TODO-add dest host in output (or key/val of tags?)
    log.info("setSecret: Successfully set secret for %s.", arn)


##TODO-add smtp endpoint as env var to test against?
def test_secret(service_client, arn, token, ses_smtp_endpoint):
    """Test the secret

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
    pending_secret = service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")['SecretString']

    secret_username, secret_password = pending_secret.split(":")

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
            except:
                log.info("login unsuccessful: %s", login_retry)
                time.sleep(1)
                login_retry -= 1
                pass
            else:
                if smtp_login[0] == 235:
                    successful = True

        if not successful:
            raise RuntimeError(f"Unable to login to smtp server : {smtp_login}")

        #TODO-revisit vars to pass

        send_ses_email(
          ses_smtp_endpoint, TEST_STAGE_SES_SMTP_PORT, secret_username, secret_password,
           TEST_STAGE_SENDER_EMAIL, TEST_STAGE_RECIPIENT_EMAIL, TEST_STAGE_EMAIL_SUBJECT, TEST_STAGE_EMAIL_BODY_TEXT, TEST_STAGE_EMAIL_BODY_HTML
        )
    else:
        log.info("testSecret: TEST_STAGE_RECIPIENT_EMAIL NOT provided, continue...")


def finish_secret(service_client, arn, token):
    """Finish the secret

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


#TODO-should likely take (from env?) in a python formated list of commands to pass to ssm send_command instead of documet_name
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
    invocationsFound = False
    retry = 10

    while not invocationsFound and retry > 0:

        if len(ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']) > 0:
            invocationsFound = True
        else:
            time.sleep(0.5)
            retry -= 1

    if not invocationsFound:
        raise RuntimeError("SSM Document was not invoked on any instances, check the tags are set correctly")


def _check_invocation_success(ssm_client, command_id):

    # Check all invocations complete, raise an error for those not successful
    invocationsComplete = False
    while not invocationsComplete:

        completeInvocations = 0

        command_invocation_status = ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']
        for invocation in command_invocation_status:

            log.info(f"finishSecret: Status of SSM Run Command on instance {invocation['InstanceId']} is {invocation['Status']}")
            if invocation['Status'] != 'Pending' and invocation['Status'] != 'InProgress':
                completeInvocations += 1

            # List isn't complete at first execution, this catches it growing
            totalInvocations = len(ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations'])

        if completeInvocations == totalInvocations:
            invocationsComplete = True
        else:
            time.sleep(5)

    # Raise an error if any were not successful
    command_invocation_status = ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']
    invocationErrors = ""
    for invocation in command_invocation_status:
        if invocation['Status'] != 'Success':
            invocationErrors += f"SSM Invocation on host {invocation['InstanceId']}  {invocation['Status']}\n"

    if invocationErrors:
        raise RuntimeError(invocationErrors)

    return


def _mark_new_secret_as_current(secret_client, secret_arn, token):

    # First describe the secret to get the current version
    metadata = secret_client.describe_secret(SecretId=secret_arn)
    current_version = None
    for version in metadata["VersionIdsToStages"]:
        if "AWSCURRENT" in metadata["VersionIdsToStages"][version]:
            if version == token:
                # The correct version is already marked as current, return
                log.info("finishSecret: Version %s already marked as AWSCURRENT for %s", version, secret_arn)
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secret_client.update_secret_version_stage(SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    log.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s.", token, secret_arn)

    return


def send_ses_email(smtp_host, smtp_port, smtp_username, smtp_password,
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
        raise RuntimeError(f"Error sending email: {e}")
