"""Unit tests for Terraform infrastructure using pytest-terraform."""

import pytest
import json
from pathlib import Path


class TestTerraformValidation:
    """Test Terraform configuration validation."""

    def test_terraform_fmt(self, terraform_dir):
        """Test that Terraform files are properly formatted."""
        import subprocess
        result = subprocess.run(
            ['terraform', 'fmt', '-check', '-diff'],
            cwd=terraform_dir,
            capture_output=True,
            text=True
        )
        assert result.returncode == 0, f"Terraform formatting issues: {result.stdout}"

    def test_terraform_validate(self, terraform_dir):
        """Test that Terraform configuration is valid."""
        import subprocess

        # Initialize terraform
        init_result = subprocess.run(
            ['terraform', 'init', '-backend=false'],
            cwd=terraform_dir,
            capture_output=True,
            text=True
        )
        assert init_result.returncode == 0, f"Terraform init failed: {init_result.stderr}"

        # Validate configuration
        validate_result = subprocess.run(
            ['terraform', 'validate'],
            cwd=terraform_dir,
            capture_output=True,
            text=True
        )
        assert validate_result.returncode == 0, f"Terraform validation failed: {validate_result.stderr}"


class TestTerraformVariables:
    """Test Terraform variable definitions."""

    def test_required_variables_defined(self):
        """Test that all required variables are defined."""
        variables_file = Path('variables.tf')
        content = variables_file.read_text()

        required_vars = [
            'project_name',
            'ses_smtp_endpoint',
            'smtp_iam_username',
            'secret_arn_for_lambda_policy'
        ]

        for var in required_vars:
            assert f'variable "{var}"' in content, f"Required variable {var} not found"

    def test_variable_validation_rules(self):
        """Test that variables have proper validation rules."""
        variables_file = Path('variables.tf')
        content = variables_file.read_text()

        # Check log_level has validation
        assert 'validation {' in content, "Variables should have validation rules"
        assert 'CRITICAL' in content, "log_level validation should include CRITICAL"


class TestTerraformResources:
    """Test Terraform resource definitions."""

    def test_lambda_module_configuration(self):
        """Test Lambda module is properly configured."""
        main_file = Path('main.tf')
        content = main_file.read_text()

        # Check Lambda module exists
        assert 'module "lambda"' in content, "Lambda module not found"
        assert 'terraform-aws-modules/terraform-aws-lambda' in content, "Lambda module source incorrect"

        # Check required Lambda configuration
        assert 'function_name = local.lambda_name' in content
        assert 'handler = "secrets_manager_rotation_by_lambda_ses_smtp_credentials.lambda_handler"' in content

    def test_iam_policy_document(self):
        """Test IAM policy document has required permissions."""
        main_file = Path('main.tf')
        content = main_file.read_text()

        required_actions = [
            'secretsmanager:GetSecretValue',
            'secretsmanager:DescribeSecret',
            'secretsmanager:PutSecretValue',
            'iam:CreateAccessKey',
            'iam:DeleteAccessKey',
            'sns:Publish'
        ]

        for action in required_actions:
            assert action in content, f"Required IAM action {action} not found"

    def test_sns_topic_configuration(self):
        """Test SNS topic is properly configured."""
        main_file = Path('main.tf')
        content = main_file.read_text()

        assert 'resource "aws_sns_topic" "rotation_notifications"' in content
        assert 'kms_master_key_id = var.sns_kms_master_key_id' in content

    def test_lambda_permission_for_secrets_manager(self):
        """Test Lambda permission for Secrets Manager is configured."""
        main_file = Path('main.tf')
        content = main_file.read_text()

        assert 'resource "aws_lambda_permission" "secretmanager"' in content
        assert 'principal = "secretsmanager.amazonaws.com"' in content


class TestTerraformVersions:
    """Test Terraform version constraints."""

    def test_terraform_version_constraint(self):
        """Test Terraform version is properly constrained."""
        versions_file = Path('versions.tf')
        content = versions_file.read_text()

        assert 'required_version = ">= 1.5.7"' in content
        assert 'required_providers' in content

    def test_aws_provider_version(self):
        """Test AWS provider version is properly constrained."""
        versions_file = Path('versions.tf')
        content = versions_file.read_text()

        assert 'source = "hashicorp/aws"' in content
        assert 'version = ">= 5.74"' in content


class TestTerraformSecurity:
    """Test Terraform security configurations."""

    def test_security_group_configuration(self):
        """Test security group allows only necessary traffic."""
        main_file = Path('main.tf')
        content = main_file.read_text()

        # Check security group exists
        assert 'resource "aws_security_group" "lambda"' in content

        # Check egress rule allows outbound traffic
        assert 'resource "aws_vpc_security_group_egress_rule" "allow_all_outbound"' in content
        assert 'ip_protocol = "-1"' in content

    def test_cloudwatch_logs_retention(self):
        """Test CloudWatch logs retention is configured."""
        variables_file = Path('variables.tf')
        content = variables_file.read_text()

        # Check default retention is set to 365 days (security requirement)
        assert 'cloudwatch_logs_retention_in_days = optional(number, 365)' in content

    def test_tracing_mode_configured(self):
        """Test X-Ray tracing is configured."""
        variables_file = Path('variables.tf')
        content = variables_file.read_text()

        # Check tracing mode is set to PassThrough (security requirement)
        assert 'tracing_mode = optional(string, "PassThrough")' in content


@pytest.fixture
def terraform_dir():
    """Fixture providing the Terraform directory path."""
    return Path('.')


@pytest.fixture
def terraform_vars():
    """Fixture providing sample Terraform variables for testing."""
    return {
        "project_name": "test-project",
        "ses_smtp_endpoint": "email-smtp.us-east-1.amazonaws.com",
        "smtp_iam_username": "test-smtp-user",
        "secret_arn_for_lambda_policy": "arn:aws:secretsmanager:us-east-1:123456789012:secret:test-secret",
        "notification_sender_email": "sender@example.com",
        "notification_recipient_email": "recipient@example.com"
    }


class TestTerraformPlan:
    """Test Terraform plan generation."""

    @pytest.mark.slow
    def test_terraform_plan_generation(self, terraform_dir, terraform_vars, tmp_path):
        """Test that Terraform plan can be generated successfully."""
        import subprocess

        # Create tfvars file
        tfvars_file = tmp_path / "test.tfvars"
        with open(tfvars_file, 'w') as f:
            for key, value in terraform_vars.items():
                if isinstance(value, str):
                    f.write(f'{key} = "{value}"\n')
                else:
                    f.write(f'{key} = {json.dumps(value)}\n')

        # Initialize terraform
        init_result = subprocess.run(
            ['terraform', 'init', '-backend=false'],
            cwd=terraform_dir,
            capture_output=True,
            text=True
        )
        assert init_result.returncode == 0, f"Terraform init failed: {init_result.stderr}"

        # Generate plan
        plan_result = subprocess.run(
            ['terraform', 'plan', f'-var-file={tfvars_file}', '-out=test.tfplan'],
            cwd=terraform_dir,
            capture_output=True,
            text=True
        )

        # Clean up plan file
        plan_file = terraform_dir / "test.tfplan"
        if plan_file.exists():
            plan_file.unlink()

        assert plan_result.returncode == 0, f"Terraform plan failed: {plan_result.stderr}"


class TestTerraformOutputs:
    """Test Terraform outputs."""

    def test_outputs_file_exists(self):
        """Test that outputs.tf file exists if outputs are defined."""
        # This is optional - add if you have outputs
        outputs_file = Path('outputs.tf')
        if outputs_file.exists():
            content = outputs_file.read_text()
            assert 'output' in content, "Outputs file should contain output definitions"