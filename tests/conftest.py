"""Pytest configuration and shared fixtures."""

import os
import sys
import pytest
from pathlib import Path

# Add src directory to Python path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

# Set environment variables for testing
os.environ.update({
    'AWS_DEFAULT_REGION': 'us-east-1',
    'AWS_REGION': 'us-east-1',
    'AWS_LAMBDA_FUNCTION_NAME': 'test-function',
    'LOG_LEVEL': 'DEBUG',
    'DRY_RUN': 'true',
    'SES_SMTP_ENDPOINT': 'email-smtp.us-east-1.amazonaws.com',
    'SMTP_IAM_USERNAME': 'test-user',
    'SSM_ROTATION_DOCUMENT_NAME': 'AWS-RunShellScript',
    'SNS_TOPIC_ARN': 'arn:aws:sns:us-east-1:123456789012:test-topic'
})


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "terraform: marks tests as terraform-specific"
    )


@pytest.fixture(scope="session")
def aws_credentials():
    """Mock AWS credentials for testing."""
    os.environ['AWS_ACCESS_KEY_ID'] = 'testing'
    os.environ['AWS_SECRET_ACCESS_KEY'] = 'testing'
    os.environ['AWS_SECURITY_TOKEN'] = 'testing'
    os.environ['AWS_SESSION_TOKEN'] = 'testing'


@pytest.fixture
def lambda_event():
    """Sample Lambda event for testing."""
    return {
        'SecretId': 'arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret',
        'ClientRequestToken': 'test-token-123',
        'Step': 'createSecret'
    }


@pytest.fixture
def lambda_context():
    """Mock Lambda context for testing."""
    class MockContext:
        def __init__(self):
            self.invoked_function_arn = 'arn:aws:lambda:us-east-1:123456789012:function:test-function'
            self.aws_request_id = 'test-request-id'
            self.log_group_name = '/aws/lambda/test-function'
            self.log_stream_name = '2024/01/01/[$LATEST]test-stream'
            self.function_name = 'test-function'
            self.function_version = '$LATEST'
            self.memory_limit_in_mb = 128

        def get_remaining_time_in_millis(self):
            return 30000

    return MockContext()


@pytest.fixture
def sample_secret_data():
    """Sample secret data for testing."""
    return {
        'username': 'test-user',
        'AccessKeyId': 'AKIATEST123456789',
        'SMTPPassword': 'test-smtp-password-123',
        'iam_user_arn': 'arn:aws:iam::123456789012:user/test-user',
        'destination_service': 'ses'
    }