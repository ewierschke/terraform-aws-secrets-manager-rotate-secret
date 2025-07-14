#!/usr/bin/env python3

# Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#ref-template from https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py
#combined w - https://github.com/aws-samples/serverless-mail/blob/main/ses-credential-rotation/ses_credential_rotator/lambda_function.py

import boto3
import logging
import os

import botocore
import hmac
import hashlib
import base64
import smtplib
import time

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger()
logger.setLevel(logging.INFO)

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

##TODO-replace/update these
SES_SMTP_HOST = "email-smtp.us-east-1.amazonaws.com"  # Example for us-east-1
SES_SMTP_PORT = 587
SENDER_EMAIL = "your_verified_sender@example.com"
RECIPIENT_EMAIL = "recipient@example.com"
EMAIL_SUBJECT = "Test Email from Python via SES"
EMAIL_BODY_TEXT = "This is a test email sent using Python and Amazon SES SMTP."
EMAIL_BODY_HTML = "<html><body><h1>Hello!</h1><p>This is a <b>test email</b> sent using Python and Amazon SES SMTP.</p></body></html>"


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
    arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']

    ##TODO - add env input details or get another way?

    # Setup the client
    service_client = boto3.client('secretsmanager', endpoint_url=os.environ['SECRETS_MANAGER_ENDPOINT'])

    # Make sure the version is staged correctly
    metadata = service_client.describe_secret(SecretId=arn)
    if not metadata['RotationEnabled']:
        logger.error("Secret %s is not enabled for rotation" % arn)
        raise ValueError("Secret %s is not enabled for rotation" % arn)
    versions = metadata['VersionIdsToStages']
    if token not in versions:
        logger.error("Secret version %s has no stage for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s has no stage for rotation of secret %s." % (token, arn))
    if "AWSCURRENT" in versions[token]:
        logger.info("Secret version %s already set as AWSCURRENT for secret %s." % (token, arn))
        return
    elif "AWSPENDING" not in versions[token]:
        logger.error("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))
        raise ValueError("Secret version %s not set as AWSPENDING for rotation of secret %s." % (token, arn))

    if step == "createSecret":
        logger.info("Executing Create Secret Function")
        region = os.environ['AWS_REGION']
        #TODO - decide about adding more params
        create_secret(service_client, arn, token)

    elif step == "setSecret":
        logger.info("Executing Set Secret Function")
        #TODO - decide about adding more params
        set_secret(service_client, arn, token)

    elif step == "testSecret":
        logger.info("Executing Test Secret Function")
        #TODO - decide about adding more params
        test_secret(service_client, arn, token)

    elif step == "finishSecret":
        logger.info("Executing Finish Secret Function")
        #TODO - decide about adding more params
        finish_secret(service_client, arn, token)

    else:
        raise ValueError("Invalid step parameter")


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def calculate_key(secret_access_key, region):
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


#TODO - decide about adding more params (where to get smtp_iam_user_name)
def create_secret(service_client, arn, token):
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
        logger.info("createSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        ## Get exclude characters from environment variable
        #exclude_characters = os.environ['EXCLUDE_CHARACTERS'] if 'EXCLUDE_CHARACTERS' in os.environ else '/@"\'\\'
        #REPLACE HERE w SMTP-- Generate a random password
        #passwd = service_client.get_random_password(ExcludeCharacters=exclude_characters)

        # Create new Access key and secret key
        iam_client = boto3.client('iam')

        keys_response = iam_client.list_access_keys(UserName=iam_user_name)
        access_keys = sorted(keys_response['AccessKeyMetadata'], key=lambda x: x['CreateDate'])

        #IAM user can have 2 keys, delete the oldest before creating a new one
        #or should the old key only be set to inactive in case it is still needed(ie revert?)
        if len(access_keys) >= 2:
            oldest_key_id = access_keys[0]['AccessKeyId']
            iam_client.delete_access_key(UserName=iam_user_name, AccessKeyId=oldest_key_id)
            logger.info("Deleted oldest access key for %s: %s", iam_user_name, oldest_key_id)

        new_key = iam_client.create_access_key(
            UserName=smtp_iam_user_name
        )

        new_access_key = new_key['AccessKey']['AccessKeyId']
        new_secret_key = new_key['AccessKey']['SecretAccessKey']

        new_smtp_secret = calculate_key(new_secret_key, region)
        new_secret = (f'{new_access_key}:{new_smtp_secret}')

        # Put the secret
        try:
            secret_client.put_secret_value(SecretId=secret_arn, ClientRequestToken=token, SecretString=new_secret, VersionStages=['AWSPENDING'])
        except botocore.exceptions.ClientError as error:

            print(error)
            print("Put secret failed, removing IAM key from user")
            iam_client.delete_access_key(
                UserName=smtp_iam_user_name,
                AccessKeyId=new_access_key
            )

            raise Exception("Secret couldn't be updated, removing IAM key pair")

        #keep for ref?
        #service_client.put_secret_value(SecretId=arn, ClientRequestToken=token, SecretString=passwd['RandomPassword'], VersionStages=['AWSPENDING'])
        logger.info("createSecret: Successfully put secret for ARN %s and version %s." % (arn, token))


##TODO-update params passed - ie based on what execute_ssm needs
def set_secret(service_client, arn, token):
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
        logger.info("setSecret: Successfully retrieved secret for %s." % arn)
    except service_client.exceptions.ResourceNotFoundException:
        raise Exception("AWSPENDING secret doesn't exist to set on service")

    currentAccessKeyId = current_secret.split(":")[0]
    secret_username, secret_password = current_secret.split(":")
    ssm_client = boto3.client('ssm')
    # Execute the SSM command against the tagged servers with the new secret
    ##TODO-update params passed
    command_id = _execute_ssm_run_command(ssm_client, document_name, server_key, server_key_value, secret_username, secret_password)

    # Wait for invocations to appear for the command
    _wait_for_ssm_invocations(ssm_client, command_id)

    # Check all complete successfully
    _check_invocation_success(ssm_client, command_id)

    ##TODO-add dest host in output (or key/val of tags?)
    logger.info("setSecret: Successfully set secret for %s." % arn)


##TODO-add smtp endpoint as env var to test against?
def test_secret(service_client, arn, token):
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
    pending_secret = secret_client.get_secret_value(SecretId=secret_arn, VersionId=token, VersionStage="AWSPENDING")['SecretString']

    secret_username, secret_password = pending_secret.split(":")

    # Create a new smtp client
    smtp_client = smtplib.SMTP_SSL(smtp_endpoint)

    # Re-try login attempts to give the new credential time to stabilise
    login_retry = 30
    successful = False

    # Loop with a delay to give the time for a credential to activate
    while login_retry != 0 and not successful:

        # Try a login to the server
        try:
            smtp_login = smtp_client.login(secret_username, secret_password)
        except:
            time.sleep(1)
            login_retry -= 1
            pass
        else:
            if smtp_login[0] == 235:
                successful = True

    if not successful:
        raise RuntimeError(f"Unable to login to smtp server : {smtp_login}")

    send_ses_email(
        SES_SMTP_HOST, SES_SMTP_PORT, secret_username, secret_password,
        SENDER_EMAIL, RECIPIENT_EMAIL, EMAIL_SUBJECT, EMAIL_BODY_TEXT, EMAIL_BODY_HTML
    )

    return


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
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, arn))


#TODO-should likely take (from env?) in a python formated list of commands to pass to ssm send_command instead of documet_name
def _execute_ssm_run_command(ssm_client, document_name, server_key, server_key_value, secret_username, secret_password):
    # Execute the provided SSM document to update and restart the email server

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
    logger.info(f"finishSecret: SSM Command ID {command_id} executed.")
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

    return


def _check_invocation_success(ssm_client, command_id):

    # Check all invocations complete, raise an error for those not successful
    invocationsComplete = False
    while not invocationsComplete:

        completeInvocations = 0

        command_invocation_status = ssm_client.list_command_invocations(CommandId=command_id)['CommandInvocations']
        for invocation in command_invocation_status:

            logger.info(f"finishSecret: Status of SSM Run Command on instance {invocation['InstanceId']} is {invocation['Status']}")
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
                logger.info("finishSecret: Version %s already marked as AWSCURRENT for %s" % (version, secret_arn))
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    secret_client.update_secret_version_stage(SecretId=secret_arn, VersionStage="AWSCURRENT", MoveToVersionId=token, RemoveFromVersionId=current_version)
    logger.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s." % (token, secret_arn))

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
        logger.info("Email sent successfully!")

    except Exception as e:
        raise RuntimeError(f"Error sending email: {e}")
