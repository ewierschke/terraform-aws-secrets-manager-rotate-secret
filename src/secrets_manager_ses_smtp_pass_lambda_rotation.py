"""Script to handle SMTP credential rotation, triggered by SecretsManager."""
#!/usr/bin/env python3

#ref-template from
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerRotationTemplate/lambda_function.py
#combined w -
# https://github.com/aws-samples/serverless-mail/blob/main/ses-credential-rotation/ses_credential_rotator/lambda_function.py
#combined w -
# https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas/blob/master/SecretsManagerElasticacheUserRotation/lambda_function.py

import base64
import collections
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from hmac import new as hmac_new
from hashlib import sha256
import json
import logging
import os
from smtplib import SMTP, SMTP_SSL, SMTPAuthenticationError
from time import sleep

from boto3 import client as boto3_client
import botocore
from botocore.exceptions import ClientError

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
SSM_ROTATE_ON_EC2_INSTANCE_ID = os.environ['SSM_ROTATE_ON_EC2_INSTANCE_ID']
SNS_TOPIC_ARN = os.environ['SNS_TOPIC_ARN']

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
    Expects Secret to be json key/value, prepopulated with username and iam_user_arn keys

    potential workflow--to allow rollback to known working IAM AKID--ties failed AWSPENDING secret 
      to an AKID to be marked inactive before raising errors?
    create_secret - checks for AKID count and status, if an inactive key is found delete first, 
      if still 2 keys found, delete oldest, mark new secret as pending
    set_secret - runs SSM commands to set pending secret in ec2 instance id, if fails, mark new AKID
      as Inactive (to allow AWSCURRENT secret to continue functioning)
    test_secret - send an email w new credential, if fails mark new AKID as Inactive
    finish_secret - changes secret label of AWSPENDING to AWSCURRENT, leaves both AKIDs active (tbd)

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
    try:
        service_client = boto3_client('secretsmanager')
        # Make sure the version is staged correctly
        metadata = service_client.describe_secret(SecretId=arn)
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ResourceNotFoundException':
            log.error("Secret %s not found", arn)
            raise ValueError(f"Secret {arn} not found") from e
        elif error_code == 'InvalidRequestException':
            log.error("Invalid request for secret %s", arn)
            raise ValueError(f"Invalid request for secret {arn}") from e
        else:
            log.error("Failed to access Secrets Manager: %s", e)
            raise RuntimeError(f"Unable to access secret {arn}: {e}") from e
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
        set_secret(service_client, arn, token, SSM_ROTATION_DOCUMENT_NAME,
                   SSM_ROTATE_ON_EC2_INSTANCE_ID)
    elif step == "testSecret":
        log.info("Executing Test Secret Function")
        #TODO - decide about adding more params... need to provide option to send email or just
        #  continue
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

    This method first checks for the existence of a secret for the passed in token. If one does not 
    exist, it will generate a new secret and put it with the passed in token.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist
    """
    # Make sure the current secret exists
    current_secret = _get_secret_dict(service_client, arn, "AWSCURRENT")

    # Verify if the username stored in environment variable is the same with the one stored
    # in current_secret
    _verify_user_name(current_secret)

    #send notification to SNS topic
    log.info("createSecret:Publishing message to topic arn %s.", SNS_TOPIC_ARN)
    sns_client = boto3_client('sns')
    topic_arn = SNS_TOPIC_ARN
    message_content = str("createSecret:Starting rotation of secret_arn: %s.", arn)
    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=message_content,
        )
        log.info("createSecret:Message published successfully with response: %s", response)
    except Exception as e:
        print(f"Error publishing message: {e}")

    # Now try to get the secret version, if that fails, put a new secret
    try:
        service_client.get_secret_value(SecretId=arn, VersionId=token, VersionStage="AWSPENDING")
        log.info("createSecret: Successfully retrieved secret for %s.", arn)
    except service_client.exceptions.ResourceNotFoundException:
        log.info("createSecret: No AWSPENDING label exists, create new for %s.", arn)
        #Generate an SMTP password

        # Create new Access key and secret key
        iam_client = boto3_client('iam')

        smtp_iam_user_arn = _get_iam_user_arn(iam_client, smtp_iam_username)

        keys_response = iam_client.list_access_keys(UserName=smtp_iam_username)
        access_keys = sorted(keys_response['AccessKeyMetadata'], key=lambda x: x['CreateDate'])

        #IAM user can have 2 keys, delete any inactive then if still 2, verify AWSCURRENT is not to
        # be deleted (if AWSCURRENT is to be deleted, del other), then delete the oldest before
        #  creating a new one
        #TODO-need to ensure we're not deleting working key to make sure for new... make sure
        # original still works until new is successfully set/tested in instance id

        #first try to del inactive then if still 2 keys, del oldest
        if len(access_keys) >= 2:
            for access_key in access_keys:
                if access_key['Status'] == 'Inactive':
                    iam_client.delete_access_key(UserName=smtp_iam_username,
                                                 AccessKeyId=access_key['AccessKeyId'])
                    log.info("Deleted Inactive access key for %s: %s", smtp_iam_username,
                             access_key['AccessKeyId'])

        #check again for 2 access keys
        iam_keys_response = iam_client.list_access_keys(UserName=smtp_iam_username)
        access_keys = sorted(iam_keys_response['AccessKeyMetadata'], key=lambda x: x['CreateDate'])
        if len(access_keys) >= 2:
            #compare the oldest key id to the key stored in AWSCURRENT, if they match AWSCURRENT is
            #still in use and should not be deleted; likely new AKID created but not rotated on app
            oldest_key_id = access_keys[0]['AccessKeyId']
            current_secret = _get_secret_dict(service_client, arn, "AWSCURRENT")
            if current_secret['AccessKeyId'] != oldest_key_id:
                iam_client.delete_access_key(UserName=smtp_iam_username, AccessKeyId=oldest_key_id)
                log.info("Deleted oldest access key for %s: %s", smtp_iam_username, oldest_key_id)
            elif current_secret['AccessKeyId'] == oldest_key_id:
                unused_key_id = access_keys[1]['AccessKeyId']
                iam_client.delete_access_key(UserName=smtp_iam_username, AccessKeyId=unused_key_id)
                log.info("Deleted access key not currently marked as AWSCURRENT in secret"
                " for %s: %s", smtp_iam_username, unused_key_id)

        new_key = iam_client.create_access_key(
            UserName=smtp_iam_username
        )
        new_access_key = new_key['AccessKey']['AccessKeyId']
        new_secret_key = new_key['AccessKey']['SecretAccessKey']

        new_smtp_secret = _calculate_key(new_secret_key, region)
        #some secret dict structure validation, expects json w four keys;
        #iam_user_arn (key must be pre-populated, func updates value to show which user the
        # generated AKID belongs to), username (value must match lambda func env var),
        # AccessKeyId, SMTPPassword
        new_secret = _get_secret_dict(service_client, arn, "AWSCURRENT")
        new_secret['iam_user_arn'] = smtp_iam_user_arn
        new_secret['AccessKeyId'] = new_access_key
        new_secret['SMTPPassword'] = new_smtp_secret

        # Put the secret
        try:
            service_client.put_secret_value(SecretId=arn, ClientRequestToken=token,
                                            SecretString=json.dumps(new_secret),
                                            VersionStages=['AWSPENDING'])
        except botocore.exceptions.ClientError as error:
            log.error("Failed to put secret value: %s", error)
            #TODO-maybe this should just mark inactive, and next go-round would check for inactive
            # to del before oldest akid?
            log.error("createSecret: Put secret failed, removing IAM key from user")
            try:
                iam_client.delete_access_key(
                    UserName=smtp_iam_username,
                    AccessKeyId=new_access_key
                )
                log.error("createSecret: Secret couldn't be updated, removing IAM key pair")
            except ClientError as cleanup_error:
                log.error("Failed to cleanup IAM access key %s: %s", new_access_key, cleanup_error)
            raise RuntimeError(f"Unable to create secret: {error}") from error

        log.info("createSecret: Successfully put secret for ARN %s and version %s.", arn, token)


def set_secret(service_client, arn, token, ssm_document_name, ssm_rotate_on_ec2_instance_id):
    """
    Set the secret

    This method should set the AWSPENDING secret in the service that the secret belongs to. 
    For example, if the secret is a database credential, this method should take the value of the
    AWSPENDING secret and set the user's password to this value in the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version
    """
    # This is where the secret should be set in the service
    # Make sure the current secret exists
    _get_secret_dict(service_client, arn, "AWSCURRENT")
    pending_secret = _get_secret_dict(service_client, arn, "AWSPENDING", token)

    # Verify if the username stored in environment variable is the same with the one stored
    #  in pending_secret
    _verify_user_name(pending_secret)

    # secret_string = pending_secret['SecretString']
    # secret_username = pending_secret['AccessKeyId']
    # secret_password = pending_secret['SMTPPassword']

    # If SSM Document name provided, and ec2 instance id
    # Execute the SSM command against the tagged servers with the new secret
    #TODO-test w commands
    if not ssm_rotate_on_ec2_instance_id == "":
        log.info("setSecret: ssm_document_name provided: %s, " \
        "attempting SSM Run Command against ec2 instance: %s", ssm_document_name, 
        ssm_rotate_on_ec2_instance_id)

        try:
            ssm_client = boto3_client('ssm')

            #TODO-verify more prescriptive; ie only run predefined script name w secret arn as parameter

            command_id = _execute_ssm_run_command(ssm_client, ssm_document_name,
                                                  ssm_rotate_on_ec2_instance_id, arn)

            # Wait for invocations to appear for the command
            _wait_for_ssm_invocations(ssm_client, command_id, ssm_rotate_on_ec2_instance_id)

            # Check all complete successfully
            _check_invocation_success(ssm_client, command_id, ssm_rotate_on_ec2_instance_id)
        except (ClientError, RuntimeError) as e:
            log.error("setSecret:Failed to execute SSM operations: %s", e)
            raise RuntimeError(f"Unable to set secret via SSM on instance {ssm_rotate_on_ec2_instance_id}: {e}") from e
    else:
        log.info("setSecret: ssm_document_name or instance_id NOT provided, no SSM actions," \
        "continue...")

    log.info("setSecret: Successfully set secret for %s against %s.", arn,
              ssm_rotate_on_ec2_instance_id)


def test_secret(service_client, arn, token, ses_smtp_endpoint):
    """
    Test the secret

    This method should validate that the AWSPENDING secret works in the service that the secret
    belongs to. For example, if the secret is a database credential, this method should validate
    that the user can login with the password in AWSPENDING and that the user has all of the
    expected permissions against the database.

    Args:
        service_client (client): The secrets manager service client

        arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version
    """
    # This is where the secret should be tested against the service
    # Get the pending secret
    # pending_secret = service_client.get_secret_value(SecretId=arn, VersionId=token,
    #  VersionStage="AWSPENDING")['SecretString']
    pending_secret = _get_secret_dict(service_client, arn, "AWSPENDING", token)

    # Verify if the username stored in environment variable is the same with the one stored
    #  in pending_secret
    _verify_user_name(pending_secret)

    secret_username = pending_secret['AccessKeyId']
    secret_password = pending_secret['SMTPPassword']

    if not TEST_STAGE_SENDER_EMAIL == "":
        # Create a new smtp client
        smtp_client = SMTP_SSL(ses_smtp_endpoint)

        # Re-try login attempts to give the new credential time to stabilise
        login_retry = 15
        successful = False

        # Loop with a delay to give the time for a credential to activate
        while login_retry != 0 and not successful:

            # Try a login to the server
            try:
                smtp_login = smtp_client.login(secret_username, secret_password)
            except SMTPAuthenticationError as e:
                #guessing at error being raised to satisfy linter-revisit
                log.info("testSecret:retry-error: %s: login unsuccessful: %s", e, login_retry)
                sleep(1)
                login_retry -= 1
            except Exception as e:  # pylint: disable=broad-exception-caught
                log.info("testSecret:retry-error: %s: login unsuccessful: %s", e, login_retry)
                sleep(1)
                login_retry -= 1
            else:
                if smtp_login[0] == 235:
                    successful = True

        if not successful:
            #TODO-should new AKID be marked inactive here?
            raise RuntimeError(f"Unable to login to smtp server : {smtp_login}")

        #TODO-revisit vars to pass
        _send_ses_email(
          ses_smtp_endpoint, TEST_STAGE_SES_SMTP_PORT, secret_username, secret_password,
           TEST_STAGE_SENDER_EMAIL, TEST_STAGE_RECIPIENT_EMAIL, TEST_STAGE_EMAIL_SUBJECT,
           TEST_STAGE_EMAIL_BODY_TEXT, TEST_STAGE_EMAIL_BODY_HTML
        )
    else:
        # mobile_key = "mobile"
        # friendly = "friendly"
        # not_friendly = "not-friendly"
        # log.info("Publishing a message with a %s: %s attribute.", mobile_key, not_friendly)
        # sns_wrapper = SnsWrapper(boto3_resource("sns"))
        log.info("testSecret:Publishing message to topic arn %s.", SNS_TOPIC_ARN)
        sns_client = boto3_client('sns')
        topic_arn = SNS_TOPIC_ARN
        # sns_wrapper.publish_message(
        #     topic_arn,
        #     "Hey. This message is not mobile friendly, so you shouldn't get "
        #     "it on your phone.",
        #     {mobile_key: not_friendly},
        # )
        message_content = str("This message from the test stage of secret rotation for secret " \
        "arn: %s.", arn)
        try:
            response = sns_client.publish(
                TopicArn=topic_arn,
                Message=message_content,
            )
            log.info("testSecret:Message published successfully with response: %s", response)
        except Exception as e:
            print(f"Error publishing message: {e}")
        # sns_wrapper.publish_message(
        #     topic_arn,
        #     "Hey. This message is not mobile friendly, so you shouldn't get "
        #     "it on your phone.",
        #     {mobile_key: not_friendly},
        # )
        log.info("testSecret: TEST_STAGE_SENDER_EMAIL NOT provided, no test email sent using SMTP" \
        "credentials, continue...")


def finish_secret(service_client, arn, token):
    """
    Finish the secret

    This method finalizes the rotation process by marking the secret version passed in as the
     AWSCURRENT secret.

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
                log.info("finishSecret: Version %s already marked as AWSCURRENT for %s", version,
                         arn)
                return
            current_version = version
            break

    # Finalize by staging the secret version current
    service_client.update_secret_version_stage(SecretId=arn, VersionStage="AWSCURRENT",
                                               MoveToVersionId=token,
                                                RemoveFromVersionId=current_version)
    log.info("finishSecret: Successfully set AWSCURRENT stage to version %s for secret %s.", token,
             arn)
    #send notification to SNS topic
    log.info("finishSecret:Publishing message to topic arn %s.", SNS_TOPIC_ARN)
    sns_client = boto3_client('sns')
    topic_arn = SNS_TOPIC_ARN
    message_content = str("finishSecret:Successfully rotated secret_arn: %s.", arn)
    try:
        response = sns_client.publish(
            TopicArn=topic_arn,
            Message=message_content,
        )
        log.info("finishSecret:Message published successfully with response: %s", response)
    except Exception as e:
        print(f"Error publishing message: {e}")


def _sign(key, msg):
    """HMAC sign"""
    return hmac_new(key, msg.encode('utf-8'), sha256).digest()


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


def _execute_ssm_run_command(ssm_client, document_name, ec2_instance_id, secret_arn):
    # Execute the provided SSM document to update and restart the email server

    log.info("_execute_ssm_run_command: secret_arn for ec2 instance to query %s.", secret_arn)

    #TODO-should not send secrets through ssm send_command, verify more prescriptive

    try:
        response = ssm_client.send_command(
            InstanceIds=[
                ec2_instance_id
            ],
            DocumentName=document_name,
            CloudWatchOutputConfig={
                'CloudWatchOutputEnabled': True
                # 'CloudWatchLogGroupName':
            },
            Comment="Run /usr/local/bin/rotate_smtp.sh after SES credential rotation",
            Parameters={
                'commands': [
                    f'export SecretId="{secret_arn}"',
                    'bash /usr/local/bin/rotate_smtp.sh $SecretId'
                ]
            },
            TimeoutSeconds=60,
        )
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'InvalidInstanceId':
            log.error("Invalid EC2 instance ID: %s", ec2_instance_id)
            raise ValueError(f"Invalid EC2 instance ID: {ec2_instance_id}") from e
        elif error_code == 'InvalidDocument':
            log.error("Invalid SSM document: %s", document_name)
            raise ValueError(f"Invalid SSM document: {document_name}") from e
        else:
            log.error("Failed to execute SSM command: %s", e)
            raise RuntimeError(f"Unable to execute SSM command on instance {ec2_instance_id}: {e}") from e
    #   Targets=[
    #       {
    #           'Key': f"tag:{server_key}",
    #           'Values': [
    #               server_key_value,
    #           ]
    #       },
    #   ],
    #   Parameters={
    #     'SESUsername': [
    #       secret_username,
    #     ],
    #     'SESPassword': [
    #       secret_password
    #     ]
    #   },
    # )

    command_id = response['Command']['CommandId']
    log.info("setSecret: SSM Command ID %s executed.", command_id)
    return command_id


def _wait_for_ssm_invocations(ssm_client, command_id, instance_id):
    # list_command_invocations starts with returning 0 invocations and gradually adds them hence
    # this logic
    invocations_found = False
    retry = 10

    while not invocations_found and retry > 0:

        if len(ssm_client.list_command_invocations(
            CommandId=command_id,InstanceId=instance_id)['CommandInvocations']) > 0:
            invocations_found = True
        else:
            sleep(0.5)
            retry -= 1

    if not invocations_found:
        raise RuntimeError(f"SSM Document was not invoked on any instances, check the instance id "
        f"{instance_id} is set correctly (command: {command_id})")


def _check_invocation_success(ssm_client, command_id, instance_id):
    # Check all invocations complete, raise an error for those not successful
    invocations_complete = False
    while not invocations_complete:

        complete_invocations = 0
        #too broad... should use get_command_invocation?  or how to limit perms
        try:
            command_invocation_status = ssm_client.list_command_invocations(
              CommandId=command_id,InstanceId=instance_id)['CommandInvocations']
        except ClientError as e:
            log.error("Failed to get SSM command invocation status: %s", e)
            raise RuntimeError(f"Unable to check SSM command status: {e}") from e

        for invocation in command_invocation_status:

            log.info("setSecret: Status of SSM Run Command on instance %s is %s",
                     invocation['InstanceId'], invocation['Status'])
            if invocation['Status'] != 'Pending' and invocation['Status'] != 'InProgress':
                complete_invocations += 1

            # List isn't complete at first execution, this catches it growing
            total_invocations = len(ssm_client.list_command_invocations(
                CommandId=command_id,InstanceId=instance_id)['CommandInvocations'])

        if complete_invocations == total_invocations:
            invocations_complete = True
        else:
            sleep(5)

    # Raise an error if any were not successful
    command_invocation_status = ssm_client.list_command_invocations(
        CommandId=command_id,InstanceId=instance_id)['CommandInvocations']
    invocation_errors = ""
    for invocation in command_invocation_status:
        if invocation['Status'] != 'Success':
            invocation_errors += f"SSM Invocation on host {invocation['InstanceId']}  {invocation['Status']}\n"

    if invocation_errors:
        #TODO-should new akid be marked inactive here?
        raise RuntimeError(invocation_errors)


def _get_secret_dict(secrets_manager_service_client, secret_arn, stage, token=None):
    """
    Gets the secret dictionary corresponding for the secret secret_arn, stage, and token
    This helper function gets credentials for the arn and stage passed in and returns the dictionary
     by parsing the JSON string

    Args:
        secrets_manager_service_client (client): The secrets manager service client

        secret_arn (string): The secret ARN or other identifier

        token (string): The ClientRequestToken associated with the secret version, or None if no 
        validation is desired

        stage (string): The stage identifying the secret version

    Returns:
        SecretDictionary: Secret dictionary

    Raises:
        ResourceNotFoundException: If the secret with the specified arn and stage does not exist

        KeyError: If the secret has no iam_user_arn
    """
    # Only do VersionId validation against the stage if a token is passed in
    if token is None:
        secret = secrets_manager_service_client.get_secret_value(SecretId=secret_arn,
                                                                VersionStage=stage)
    else:
        secret = secrets_manager_service_client.get_secret_value(SecretId=secret_arn,
                                                                VersionId=token,
                                                                VersionStage=stage)
    plaintext = secret['SecretString']
    try:
        secret_dict = json.loads(plaintext)
    except Exception as exc:
        # wrapping json parser exceptions to avoid possible password disclosure
        log.error("Invalid secret value json for secret %s.", secret_arn)
        raise ValueError(f"Invalid secret value json for secret {secret_arn}.") from exc

    # Validates if there is a user associated to the secret
    if "iam_user_arn" not in secret_dict:
        log.error("createSecret: secret %s has no iam_user_arn defined.", secret_arn)
        raise KeyError(f"createSecret: secret {secret_arn} has no iam_user_arn defined.")

    return secret_dict


def _verify_user_name(secret):
    """
    Verify whether SMTP_IAM_USERNAME set in Lambda environment variable matches what's set in the
    secret

    Args:
        secret: The secret from Secrets Manager
    
    Raises:
        verificationException: username in Lambda environment variable doesn't match the one stored 
        in the secret
    """
    env_iam_smtp_user_name = os.environ['SMTP_IAM_USERNAME']
    secret_user_name = secret["username"]
    if env_iam_smtp_user_name != secret_user_name:
        log.error("User %s is not allowed to use this Lambda function for rotation",
                  secret_user_name)
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
        
        smtp_password (str): Your Amazon SES SMTP password (Secret Access Key converted to an SMTP
          password).
        
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
        server = SMTP(smtp_host, smtp_port)
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
        #TODO-should new AKID be marked inactive here?
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
        iam_user_arn = response['User']['Arn']
        return iam_user_arn
    except iam_service_client.exceptions.NoSuchEntityException:
        log.error("IAM user '%s' not found", username)
        return None
    except Exception as e: # pylint: disable=broad-exception-caught
        log.error("Failed to get IAM user ARN for '%s': %s", username, e)
        return None


# #https://github.com/awsdocs/aws-doc-sdk-examples/blob/main/python/example_code/sns/sns_basics.py#L339
# class SnsWrapper:
#     """Encapsulates Amazon SNS topic and subscription functions."""

#     def __init__(self, sns_resource):
#         """
#         :param sns_resource: A Boto3 Amazon SNS resource.
#         """
#         self.sns_resource = sns_resource


#     @staticmethod
#     def publish_message(topic, message, attributes):
#         """
#         Publishes a message, with attributes, to a topic. Subscriptions can be filtered
#         based on message attributes so that a subscription receives messages only
#         when specified attributes are present.

#         :param topic: The topic to publish to.
#         :param message: The message to publish.
#         :param attributes: The key-value attributes to attach to the message. Values
#                            must be either `str` or `bytes`.
#         :return: The ID of the message.
#         """
#         try:
#             att_dict = {}
#             for key, value in attributes.items():
#                 if isinstance(value, str):
#                     att_dict[key] = {"DataType": "String", "StringValue": value}
#                 elif isinstance(value, bytes):
#                     att_dict[key] = {"DataType": "Binary", "BinaryValue": value}
#             response = topic.publish(Message=message, MessageAttributes=att_dict)
#             message_id = response["MessageId"]
#             log.info(
#                 "Published message with attributes %s to topic %s.",
#                 attributes,
#                 topic.arn,
#             )
#         except ClientError as e:
#             log.error("Failed to publish message to topic %s: %s", topic.arn, e)
#             raise RuntimeError(f"Unable to publish SNS message to topic {topic.arn}: {e}") from e
#         else:
#             return message_id
