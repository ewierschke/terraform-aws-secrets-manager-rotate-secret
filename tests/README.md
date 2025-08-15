# Testing Framework for SES SMTP Rotation Lambda

This directory contains a comprehensive testing framework for both the Python Lambda function and Terraform infrastructure.

## Structure

```
tests/
├── unit/
│   ├── test_lambda_function.py    # Python Lambda function unit tests
│   └── test_terraform.py          # Terraform configuration tests
├── integration/
│   └── test_end_to_end.py         # End-to-end integration tests
├── conftest.py                    # Pytest configuration and fixtures
├── requirements.txt               # Testing dependencies
└── README.md                      # This file
```

## Test Categories

### Unit Tests

#### Python Lambda Tests (`test_lambda_function.py`)
- **TestLambdaHandler**: Main lambda_handler function tests
- **TestCreateSecret**: Secret creation workflow tests
- **TestCalculateKey**: SMTP password calculation tests
- **TestVerifyUserName**: Username verification tests
- **TestSendSesEmail**: Email sending functionality tests
- **TestPublishSns**: SNS notification tests
- **TestIntegration**: Integration workflow tests

#### Terraform Tests (`test_terraform.py`)
- **TestTerraformValidation**: Format and validation checks
- **TestTerraformVariables**: Variable definition and validation tests
- **TestTerraformResources**: Resource configuration tests
- **TestTerraformVersions**: Version constraint tests
- **TestTerraformSecurity**: Security configuration tests
- **TestTerraformPlan**: Plan generation tests

### Integration Tests

#### End-to-End Tests (`test_end_to_end.py`)
- **TestEndToEndRotation**: Complete rotation workflow tests
- **TestTerraformIntegration**: Terraform integration tests

## Running Tests

### Prerequisites

```bash
# Install test dependencies
pip install -r tests/requirements.txt
pip install -r src/requirements.txt

# For Terraform tests
terraform --version  # Ensure Terraform is installed
```

### Quick Start

```bash
# Run all tests
make test

# Run only unit tests
make test-unit

# Run only Terraform tests
make test-terraform

# Run with coverage
make test-coverage
```

### Detailed Test Commands

```bash
# Python unit tests only
pytest tests/unit/test_lambda_function.py -v

# Terraform tests only
pytest tests/unit/test_terraform.py -v -m terraform

# Integration tests
pytest tests/integration/ -v -m integration

# Fast tests (exclude slow tests)
pytest tests/unit/ -v -m "not slow"

# Run tests in parallel
pytest tests/unit/ -n auto

# Generate HTML coverage report
pytest tests/unit/ --cov=src --cov-report=html
```

## Test Configuration

### Pytest Configuration (`pytest.ini`)
- Test discovery patterns
- Coverage settings (80% minimum)
- Custom markers for test categorization
- Output formatting

### Environment Variables
Tests use these environment variables (set in `conftest.py`):
- `AWS_REGION`: us-east-1
- `AWS_LAMBDA_FUNCTION_NAME`: test-function
- `LOG_LEVEL`: DEBUG
- `SMTP_IAM_USERNAME`: test-user
- `SNS_TOPIC_ARN`: test topic ARN

### Fixtures (`conftest.py`)
- `aws_credentials`: Mock AWS credentials
- `lambda_event`: Sample Lambda event
- `lambda_context`: Mock Lambda context
- `sample_secret_data`: Sample secret data structure

## Mocking Strategy

### AWS Services
- **moto**: Mock AWS services (Secrets Manager, IAM, SNS, SSM)
- **unittest.mock**: Mock external dependencies (SMTP, HTTP calls)

### Terraform
- **subprocess**: Execute Terraform commands for validation
- **pytest-terraform**: Terraform-specific testing utilities

## Test Markers

Use pytest markers to categorize and run specific test types:

```bash
# Run only fast tests
pytest -m "not slow"

# Run only integration tests
pytest -m integration

# Run only Terraform tests
pytest -m terraform
```

## Coverage Requirements

- **Minimum Coverage**: 80%
- **Coverage Reports**: HTML and terminal output
- **Exclusions**: Test files, virtual environments

## CI/CD Integration

### GitHub Actions (`.github/workflows/test.yml`)
- Multi-Python version testing (3.9-3.12)
- Terraform validation
- Security scanning
- Coverage reporting

### Tox (`tox.ini`)
- Multi-environment testing
- Isolated test environments
- Lint and security checks

## Quality Checks

### Code Quality
```bash
# Linting
flake8 src/ tests/ --max-line-length=100

# Formatting
black src/ tests/
isort src/ tests/

# Type checking
mypy src/ --ignore-missing-imports
```

### Security Scanning
```bash
# Security vulnerabilities
bandit -r src/
safety check
```

## Best Practices

### Writing Tests
1. **Descriptive Names**: Use clear, descriptive test names
2. **Single Responsibility**: Each test should test one thing
3. **Arrange-Act-Assert**: Structure tests clearly
4. **Mock External Dependencies**: Don't make real AWS calls
5. **Use Fixtures**: Reuse common test data and setup

### Test Organization
1. **Group Related Tests**: Use test classes for organization
2. **Mark Slow Tests**: Use `@pytest.mark.slow` for long-running tests
3. **Separate Unit/Integration**: Keep different test types separate
4. **Document Complex Tests**: Add docstrings for complex test scenarios

### Terraform Testing
1. **Validate Syntax**: Always check `terraform fmt` and `terraform validate`
2. **Test Variables**: Verify required variables and validation rules
3. **Check Security**: Test security group rules and IAM policies
4. **Plan Generation**: Test that plans can be generated successfully

## Troubleshooting

### Common Issues

#### Import Errors
```bash
# Ensure src is in Python path
export PYTHONPATH="${PYTHONPATH}:src"
```

#### AWS Credential Errors
```bash
# Moto should handle this, but if needed:
export AWS_ACCESS_KEY_ID=testing
export AWS_SECRET_ACCESS_KEY=testing
```

#### Terraform Command Not Found
```bash
# Install Terraform
# macOS: brew install terraform
# Ubuntu: apt-get install terraform
# Windows: choco install terraform
```

### Debug Mode
```bash
# Run tests with verbose output and no capture
pytest tests/unit/ -v -s --tb=long

# Run specific test with debugging
pytest tests/unit/test_lambda_function.py::TestLambdaHandler::test_lambda_handler_create_secret -v -s
```

## Contributing

When adding new tests:

1. **Follow Naming Conventions**: `test_*.py` files, `Test*` classes, `test_*` methods
2. **Add Appropriate Markers**: Use `@pytest.mark.slow` or `@pytest.mark.integration`
3. **Update Documentation**: Update this README if adding new test categories
4. **Maintain Coverage**: Ensure new code is covered by tests
5. **Test Both Success and Failure**: Test happy path and error conditions