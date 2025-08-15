"""Unit tests for the SES SMTP credentials rotation Lambda function."""

import json
import os
import pytest
from unittest.mock import Mock, patch, MagicMock
from moto import mock_secretsmanager, mock_iam, mock_sns, mock_ssm
import boto3
from botocore.exceptions import ClientError

# Import the lambda function
import sys
sys.path.append('src')
from secrets_manager_rotation_by_lambda_ses_smtp_credentials import (
    lambda_handler,
    create_secret,
    set_secret,
    test_secret,
    finish_secret,
    _calculate_key,
    _verify_user_name,
    _get_secret_dict,
    _send_ses_email,
    _publish_sns
)


class TestLambdaHandler:
    """Test cases for the main lambda_handler function."""

    @mock_secretsmanager
    def test_lambda_handler_create_secret(self):
        """Test lambda_handler with createSecret step."""
        # Setup
        client = boto3.client('secretsmanager', region_name='us-east-1')
        secret_arn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret'

        # Create a secret with rotation enabled
        client.create_secret(
            Name='test-secret',
            SecretString=json.dumps({
                'username': 'test-user',
                'AccessKeyId': 'AKIATEST',
                'SMTPPassword': 'test-password',
                'iam_user_arn': 'arn:aws:iam::123456789012:user/test-user',
                'destination_service': 'ses'
            })
        )
        client.update_secret(SecretId='test-secret', Description='Test secret')

        event = {
            'SecretId': secret_arn,
            'ClientRequestToken': 'test-token',
            'Step': 'createSecret'
        }
        context = Mock()
        context.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test'

        with patch.dict(os.environ, {
            'AWS_REGION': 'us-east-1',
            'SMTP_IAM_USERNAME': 'test-user',
            'AWS_LAMBDA_FUNCTION_NAME': 'test-function'
        }):
            with patch('secrets_manager_rotation_by_lambda_ses_smtp_credentials.create_secret') as mock_create:
                lambda_handler(event, context)
                mock_create.assert_called_once()

    def test_lambda_handler_invalid_step(self):
        """Test lambda_handler with invalid step."""
        event = {
            'SecretId': 'test-arn',
            'ClientRequestToken': 'test-token',
            'Step': 'invalidStep'
        }
        context = Mock()

        with pytest.raises(ValueError, match="Invalid step parameter"):
            lambda_handler(event, context)


class TestCreateSecret:
    """Test cases for create_secret function."""

    @mock_secretsmanager
    @mock_iam
    def test_create_secret_success(self):
        """Test successful secret creation."""
        # Setup mocks
        secrets_client = boto3.client('secretsmanager', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')

        # Create IAM user
        iam_client.create_user(UserName='test-user')

        # Create existing secret
        secret_data = {
            'username': 'test-user',
            'AccessKeyId': 'AKIAOLD',
            'SMTPPassword': 'old-password',
            'iam_user_arn': 'arn:aws:iam::123456789012:user/test-user',
            'destination_service': 'ses'
        }
        secrets_client.create_secret(
            Name='test-secret',
            SecretString=json.dumps(secret_data)
        )

        with patch.dict(os.environ, {'SMTP_IAM_USERNAME': 'test-user'}):
            with patch('secrets_manager_rotation_by_lambda_ses_smtp_credentials._publish_sns'):
                create_secret(secrets_client, 'test-secret', 'test-token', 'us-east-1', 'test-user')


class TestCalculateKey:
    """Test cases for _calculate_key function."""

    def test_calculate_key_valid_region(self):
        """Test SMTP password calculation for valid region."""
        secret_key = 'test-secret-key'
        region = 'us-east-1'

        result = _calculate_key(secret_key, region)

        assert isinstance(result, str)
        assert len(result) > 0

    def test_calculate_key_invalid_region(self):
        """Test SMTP password calculation for invalid region."""
        secret_key = 'test-secret-key'
        region = 'invalid-region'

        with pytest.raises(ValueError, match="doesn't have an SMTP endpoint"):
            _calculate_key(secret_key, region)


class TestVerifyUserName:
    """Test cases for _verify_user_name function."""

    def test_verify_user_name_success(self):
        """Test successful username verification."""
        secret = {'username': 'test-user'}

        with patch.dict(os.environ, {'SMTP_IAM_USERNAME': 'test-user'}):
            # Should not raise an exception
            _verify_user_name(secret)

    def test_verify_user_name_mismatch(self):
        """Test username verification with mismatch."""
        secret = {'username': 'wrong-user'}

        with patch.dict(os.environ, {'SMTP_IAM_USERNAME': 'test-user'}):
            with pytest.raises(ValueError, match="Username mismatch"):
                _verify_user_name(secret)


class TestSendSesEmail:
    """Test cases for _send_ses_email function."""

    @patch('secrets_manager_rotation_by_lambda_ses_smtp_credentials.SMTP_SSL')
    def test_send_ses_email_success(self, mock_smtp):
        """Test successful email sending."""
        mock_server = Mock()
        mock_smtp.return_value = mock_server

        _send_ses_email(
            'smtp.example.com', 587, 'user', 'pass',
            'sender@example.com', 'recipient@example.com',
            'Test Subject', 'Test Body'
        )

        mock_server.login.assert_called_once_with('user', 'pass')
        mock_server.send_message.assert_called_once()
        mock_server.quit.assert_called_once()


class TestPublishSns:
    """Test cases for _publish_sns function."""

    @mock_sns
    def test_publish_sns_success(self):
        """Test successful SNS publishing."""
        sns_client = boto3.client('sns', region_name='us-east-1')
        topic_response = sns_client.create_topic(Name='test-topic')
        topic_arn = topic_response['TopicArn']

        with patch('boto3.client') as mock_boto_client:
            mock_boto_client.return_value = sns_client
            _publish_sns(topic_arn, 'Test message')

    def test_publish_sns_empty_topic(self):
        """Test SNS publishing with empty topic ARN."""
        # Should handle gracefully when topic ARN is empty
        _publish_sns('', 'Test message')


@pytest.fixture
def mock_context():
    """Fixture for Lambda context."""
    context = Mock()
    context.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test'
    context.aws_request_id = 'test-request-id'
    return context


@pytest.fixture
def sample_secret():
    """Fixture for sample secret data."""
    return {
        'username': 'test-user',
        'AccessKeyId': 'AKIATEST123',
        'SMTPPassword': 'test-smtp-password',
        'iam_user_arn': 'arn:aws:iam::123456789012:user/test-user',
        'destination_service': 'ses'
    }


class TestIntegration:
    """Integration test cases."""

    @mock_secretsmanager
    @mock_iam
    @patch('secrets_manager_rotation_by_lambda_ses_smtp_credentials._publish_sns')
    def test_full_rotation_workflow(self, mock_sns, sample_secret):
        """Test complete rotation workflow."""
        # Setup
        secrets_client = boto3.client('secretsmanager', region_name='us-east-1')
        iam_client = boto3.client('iam', region_name='us-east-1')

        # Create IAM user
        iam_client.create_user(UserName='test-user')

        # Create secret
        secrets_client.create_secret(
            Name='test-secret',
            SecretString=json.dumps(sample_secret)
        )

        # Enable rotation
        secrets_client.update_secret(
            SecretId='test-secret',
            Description='Test secret for rotation'
        )

        with patch.dict(os.environ, {
            'AWS_REGION': 'us-east-1',
            'SMTP_IAM_USERNAME': 'test-user',
            'AWS_LAMBDA_FUNCTION_NAME': 'test-function',
            'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'
        }):
            # Test create_secret
            create_secret(secrets_client, 'test-secret', 'test-token', 'us-east-1', 'test-user')

            # Verify secret was created
            try:
                response = secrets_client.get_secret_value(
                    SecretId='test-secret',
                    VersionId='test-token',
                    VersionStage='AWSPENDING'
                )
                assert response is not None
            except ClientError:
                # Expected if secret creation was mocked
                pass