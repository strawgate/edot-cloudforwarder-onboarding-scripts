"""Tests for the CLI module."""

from edot_discovery.cli import (
    LOG_TYPE_MAP,
    extract_bucket_arn,
    generate_cloudformation_command,
    generate_stack_name,
    redact_command_for_display,
    validate_otlp_endpoint,
)


class TestExtractBucketArn:
    """Tests for extract_bucket_arn function."""

    def test_arn_format_with_prefix(self):
        """Test extracting bucket ARN from ARN format with prefix."""
        destination = "arn:aws:s3:::my-bucket/prefix/subprefix/"
        result = extract_bucket_arn(destination)
        assert result == "arn:aws:s3:::my-bucket"

    def test_arn_format_without_prefix(self):
        """Test extracting bucket ARN from ARN format without prefix."""
        destination = "arn:aws:s3:::my-bucket"
        result = extract_bucket_arn(destination)
        assert result == "arn:aws:s3:::my-bucket"

    def test_s3_url_format_with_prefix(self):
        """Test extracting bucket ARN from s3:// format with prefix."""
        destination = "s3://my-bucket/prefix/"
        result = extract_bucket_arn(destination)
        assert result == "arn:aws:s3:::my-bucket"

    def test_s3_url_format_without_prefix(self):
        """Test extracting bucket ARN from s3:// format without prefix."""
        destination = "s3://my-bucket"
        result = extract_bucket_arn(destination)
        assert result == "arn:aws:s3:::my-bucket"

    def test_unknown_format_passthrough(self):
        """Test that unknown formats are passed through unchanged."""
        destination = "unknown-format"
        result = extract_bucket_arn(destination)
        assert result == "unknown-format"


class TestGenerateStackName:
    """Tests for generate_stack_name function."""

    def test_basic_vpc_flow_logs(self):
        """Test stack name generation for VPC flow logs."""
        bucket_arn = "arn:aws:s3:::my-vpc-logs"
        log_type = "vpc_flow_logs"
        result = generate_stack_name(bucket_arn, log_type)
        assert result == "edot-cf-vpcflow-my-vpc-logs"
        assert result[0].isalpha()
        assert len(result) <= 128

    def test_basic_elb_access_logs(self):
        """Test stack name generation for ELB access logs."""
        bucket_arn = "arn:aws:s3:::my-elb-logs"
        log_type = "elb_access_logs"
        result = generate_stack_name(bucket_arn, log_type)
        assert result == "edot-cf-elbaccess-my-elb-logs"
        assert result[0].isalpha()
        assert len(result) <= 128

    def test_special_characters_sanitized(self):
        """Test that special characters are sanitized."""
        bucket_arn = "arn:aws:s3:::my.bucket_name"
        log_type = "vpc_flow_logs"
        result = generate_stack_name(bucket_arn, log_type)
        # Dots and underscores should be replaced with hyphens
        assert "." not in result
        assert "_" not in result
        assert result[0].isalpha()

    def test_numeric_start_handled(self):
        """Test that bucket names starting with numbers are handled."""
        bucket_arn = "arn:aws:s3:::123-bucket"
        log_type = "vpc_flow_logs"
        result = generate_stack_name(bucket_arn, log_type)
        assert result[0].isalpha()

    def test_long_name_truncated(self):
        """Test that long names are truncated with hash."""
        bucket_arn = "arn:aws:s3:::" + "a" * 150
        log_type = "vpc_flow_logs"
        result = generate_stack_name(bucket_arn, log_type)
        assert len(result) <= 128
        assert result[0].isalpha()

    def test_deterministic(self):
        """Test that same inputs produce same output."""
        bucket_arn = "arn:aws:s3:::my-logs"
        log_type = "vpc_flow_logs"
        result1 = generate_stack_name(bucket_arn, log_type)
        result2 = generate_stack_name(bucket_arn, log_type)
        assert result1 == result2


class TestGenerateCloudformationCommand:
    """Tests for generate_cloudformation_command function."""

    def test_returns_list(self):
        """Test that the function returns a list."""
        result = generate_cloudformation_command(
            stack_name="test-stack",
            log_type="vpc_flow_logs",
            bucket_arn="arn:aws:s3:::my-bucket",
            otlp_endpoint="https://example.com",
            api_key="test-key",
            region="us-east-1",
        )
        assert isinstance(result, list)
        assert result[0] == "aws"
        assert result[1] == "cloudformation"

    def test_log_type_mapping(self):
        """Test that log types are mapped correctly."""
        result = generate_cloudformation_command(
            stack_name="test-stack",
            log_type="vpc_flow_logs",
            bucket_arn="arn:aws:s3:::my-bucket",
            otlp_endpoint="https://example.com",
            api_key="test-key",
            region="us-east-1",
        )
        # Find the parameter with log type using next() instead of list comprehension
        log_type_param = next((p for p in result if "EdotCloudForwarderS3LogsType" in p), None)
        assert log_type_param is not None
        assert "vpcflow" in log_type_param

    def test_all_parameters_present(self):
        """Test that all required parameters are in the command."""
        result = generate_cloudformation_command(
            stack_name="test-stack",
            log_type="vpc_flow_logs",
            bucket_arn="arn:aws:s3:::my-bucket",
            otlp_endpoint="https://example.com",
            api_key="test-key",
            region="us-east-1",
        )
        result_str = " ".join(result)
        assert "--stack-name" in result_str
        assert "test-stack" in result_str
        assert "--template-url" in result_str
        assert "--region" in result_str
        assert "us-east-1" in result_str
        assert "CAPABILITY_NAMED_IAM" in result_str


class TestRedactCommandForDisplay:
    """Tests for redact_command_for_display function."""

    def test_redacts_elastic_api_key(self):
        """Test that ElasticAPIKey parameter is redacted."""
        cmd = [
            "aws",
            "cloudformation",
            "create-stack",
            "ParameterKey=ElasticAPIKey,ParameterValue=secret-key-123",
        ]
        result = redact_command_for_display(cmd)
        assert "secret-key-123" not in result
        assert "<REDACTED>" in result

    def test_redacts_api_key_env_style(self):
        """Test that API_KEY= style is redacted."""
        cmd = ["aws", "cloudformation", "API_KEY=secret"]
        result = redact_command_for_display(cmd)
        assert "secret" not in result
        assert "API_KEY=<REDACTED>" in result

    def test_preserves_non_sensitive_values(self):
        """Test that non-sensitive values are preserved."""
        cmd = [
            "aws",
            "cloudformation",
            "create-stack",
            "--stack-name",
            "my-stack",
            "--region",
            "us-east-1",
        ]
        result = redact_command_for_display(cmd)
        assert "my-stack" in result
        assert "us-east-1" in result


class TestValidateOtlpEndpoint:
    """Tests for validate_otlp_endpoint function."""

    def test_valid_https_endpoint(self):
        """Test valid HTTPS endpoint."""
        assert validate_otlp_endpoint("https://example.apm.aws.cloud.es.io:443") is True

    def test_valid_https_endpoint_simple(self):
        """Test valid simple HTTPS endpoint."""
        assert validate_otlp_endpoint("https://example.com") is True

    def test_rejects_http(self):
        """Test that HTTP endpoints are rejected."""
        assert validate_otlp_endpoint("http://example.com") is False

    def test_rejects_empty(self):
        """Test that empty string is rejected."""
        assert validate_otlp_endpoint("") is False

    def test_rejects_none(self):
        """Test that None is rejected without raising an exception."""
        assert validate_otlp_endpoint(None) is False

    def test_rejects_no_domain(self):
        """Test that URLs without a proper domain are rejected."""
        assert validate_otlp_endpoint("https://nodomain") is False

    def test_accepts_localhost(self):
        """Test that localhost is accepted as a valid host."""
        assert validate_otlp_endpoint("https://localhost:8080") is True

    def test_rejects_invalid_scheme(self):
        """Test that non-HTTPS schemes are rejected."""
        assert validate_otlp_endpoint("ftp://example.com") is False


class TestLogTypeMap:
    """Tests for LOG_TYPE_MAP constant."""

    def test_vpc_flow_logs_mapping(self):
        """Test VPC flow logs mapping."""
        assert LOG_TYPE_MAP["vpc_flow_logs"] == "vpcflow"

    def test_elb_access_logs_mapping(self):
        """Test ELB access logs mapping."""
        assert LOG_TYPE_MAP["elb_access_logs"] == "elbaccess"

    def test_cloudtrail_mapping(self):
        """Test CloudTrail mapping."""
        assert LOG_TYPE_MAP["cloudtrail"] == "cloudtrail"
