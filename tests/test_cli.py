"""Tests for the CLI module."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from edot_discovery.cli import generate_deployment_commands
from edot_discovery.discovery.types import LogSource
from edot_discovery.discovery.utils import (
    LOG_TYPE_MAP,
    extract_bucket_arn,
    generate_cloudformation_command,
    generate_stack_name,
    get_bucket_region,
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

    def test_waf_mapping(self):
        """Test WAF mapping."""
        assert LOG_TYPE_MAP["waf"] == "waf"


class TestGetBucketRegion:
    """Tests for get_bucket_region function."""

    def test_standard_region(self):
        """Test getting bucket region for a standard region."""
        bucket_arn = "arn:aws:s3:::my-bucket"
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "us-west-2"}

        result = get_bucket_region(bucket_arn, mock_session)

        assert result == "us-west-2"
        mock_s3_client.get_bucket_location.assert_called_once_with(Bucket="my-bucket")

    def test_us_east_1_returns_none(self):
        """Test that us-east-1 returns None from API and is handled correctly."""
        bucket_arn = "arn:aws:s3:::my-bucket"
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        # us-east-1 returns None for LocationConstraint
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}

        result = get_bucket_region(bucket_arn, mock_session)

        assert result == "us-east-1"

    def test_empty_location_constraint_handled(self):
        """Test that empty location constraint is handled as us-east-1."""
        bucket_arn = "arn:aws:s3:::my-bucket"
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.return_value = {}

        result = get_bucket_region(bucket_arn, mock_session)

        assert result == "us-east-1"

    def test_client_error_returns_none(self):
        """Test that ClientError returns None."""
        bucket_arn = "arn:aws:s3:::my-bucket"
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucket", "Message": "Bucket not found"}}, "GetBucketLocation"
        )

        result = get_bucket_region(bucket_arn, mock_session)

        assert result is None

    def test_generic_exception_returns_none(self):
        """Test that generic exceptions return None."""
        bucket_arn = "arn:aws:s3:::my-bucket"
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.side_effect = Exception("Unexpected error")

        result = get_bucket_region(bucket_arn, mock_session)

        assert result is None

    def test_creates_session_if_none_provided(self):
        """Test that function creates a session if none is provided."""
        bucket_arn = "arn:aws:s3:::my-bucket"
        with patch("edot_discovery.discovery.utils.boto3.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_s3_client = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.client.return_value = mock_s3_client
            mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

            result = get_bucket_region(bucket_arn)

            assert result == "eu-west-1"
            mock_session_class.assert_called_once()

    def test_extracts_bucket_name_from_arn(self):
        """Test that bucket name is correctly extracted from ARN."""
        bucket_arn = "arn:aws:s3:::my-complex-bucket-name"
        mock_session = MagicMock()
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "ap-southeast-1"}

        result = get_bucket_region(bucket_arn, mock_session)

        assert result == "ap-southeast-1"
        mock_s3_client.get_bucket_location.assert_called_once_with(Bucket="my-complex-bucket-name")


class TestGenerateDeploymentCommands:
    """Tests for generate_deployment_commands function."""

    @pytest.fixture
    def sample_source_same_region(self):
        """Sample LogSource with bucket in same region as resource."""
        return LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-123",
            resource_id="vpc-abc",
            destination="s3://my-bucket/logs/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-east-1",
        )

    @pytest.fixture
    def sample_source_cross_region(self):
        """Sample LogSource with bucket in different region than resource."""
        return LogSource(
            log_type="elb_access_logs",
            display_type="ALB Access Logs",
            source_id="my-alb",
            resource_id="arn:aws:elasticloadbalancing:us-west-2:123:loadbalancer/app/my-alb/abc",
            destination="s3://my-bucket/alb/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-west-2",  # Resource in us-west-2
        )

    @pytest.fixture
    def mock_session(self):
        """Mock boto3 session."""
        return MagicMock()

    def test_same_region_deployment(self, sample_source_same_region, mock_session):
        """Test deployment when bucket and resource are in same region."""
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        # Bucket is in us-east-1 (same as resource)
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}

        commands = generate_deployment_commands(
            [sample_source_same_region], "https://example.com", "test-api-key", mock_session
        )

        assert len(commands) == 1
        display_name, bucket_arn, log_type, cmd = commands[0]
        assert display_name == "VPC Flow Logs"
        assert bucket_arn == "arn:aws:s3:::my-bucket"
        assert log_type == "vpc_flow_logs"
        # Check that region is us-east-1 (bucket region, not resource region)
        assert "--region" in cmd
        region_idx = cmd.index("--region")
        assert cmd[region_idx + 1] == "us-east-1"

    def test_cross_region_deployment(self, sample_source_cross_region, mock_session):
        """Test deployment when bucket and resource are in different regions."""
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        # Bucket is in us-east-1, resource is in us-west-2
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}

        commands = generate_deployment_commands(
            [sample_source_cross_region], "https://example.com", "test-api-key", mock_session
        )

        assert len(commands) == 1
        display_name, bucket_arn, log_type, cmd = commands[0]
        # Should deploy in bucket region (us-east-1), not resource region (us-west-2)
        assert "--region" in cmd
        region_idx = cmd.index("--region")
        assert cmd[region_idx + 1] == "us-east-1"

    def test_multiple_sources_same_bucket(self, mock_session):
        """Test grouping multiple sources with same bucket."""
        source1 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://my-bucket/vpc/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-east-1",
        )
        source2 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-2",
            resource_id="vpc-2",
            destination="s3://my-bucket/vpc/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-west-2",
        )
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

        commands = generate_deployment_commands(
            [source1, source2], "https://example.com", "test-api-key", mock_session
        )

        # Should generate only one command for same bucket+log_type
        assert len(commands) == 1
        # Should use bucket region (eu-west-1), not resource regions
        _, _, _, cmd = commands[0]
        assert "--region" in cmd
        region_idx = cmd.index("--region")
        assert cmd[region_idx + 1] == "eu-west-1"

    def test_different_buckets_generate_separate_commands(self, mock_session):
        """Test that different buckets generate separate commands."""
        source1 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://bucket-1/vpc/",
            bucket_arn="arn:aws:s3:::bucket-1",
            region="us-east-1",
        )
        source2 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-2",
            resource_id="vpc-2",
            destination="s3://bucket-2/vpc/",
            bucket_arn="arn:aws:s3:::bucket-2",
            region="us-east-1",
        )
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        # First bucket in us-east-1, second in us-west-2
        mock_s3_client.get_bucket_location.side_effect = [
            {"LocationConstraint": None},  # bucket-1 -> us-east-1
            {"LocationConstraint": "us-west-2"},  # bucket-2 -> us-west-2
        ]

        commands = generate_deployment_commands(
            [source1, source2], "https://example.com", "test-api-key", mock_session
        )

        assert len(commands) == 2
        # Check first command uses bucket-1 region
        _, bucket_arn1, _, cmd1 = commands[0]
        assert bucket_arn1 == "arn:aws:s3:::bucket-1"
        assert "--region" in cmd1
        region_idx1 = cmd1.index("--region")
        assert cmd1[region_idx1 + 1] == "us-east-1"

        # Check second command uses bucket-2 region
        _, bucket_arn2, _, cmd2 = commands[1]
        assert bucket_arn2 == "arn:aws:s3:::bucket-2"
        assert "--region" in cmd2
        region_idx2 = cmd2.index("--region")
        assert cmd2[region_idx2 + 1] == "us-west-2"

    def test_different_log_types_generate_separate_commands(self, mock_session):
        """Test that different log types for same bucket generate separate commands."""
        source1 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://my-bucket/vpc/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-east-1",
        )
        source2 = LogSource(
            log_type="elb_access_logs",
            display_type="ELB Access Logs",
            source_id="alb-1",
            resource_id="arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb/abc",
            destination="s3://my-bucket/alb/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-east-1",
        )
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}

        commands = generate_deployment_commands(
            [source1, source2], "https://example.com", "test-api-key", mock_session
        )

        assert len(commands) == 2
        log_types = {log_type for _, _, log_type, _ in commands}
        assert "vpc_flow_logs" in log_types
        assert "elb_access_logs" in log_types

    def test_fallback_to_resource_region_on_error(self, mock_session):
        """Test that function falls back to resource region when bucket region unavailable."""
        source = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://my-bucket/vpc/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-west-2",
        )
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access denied"}}, "GetBucketLocation"
        )

        commands = generate_deployment_commands(
            [source], "https://example.com", "test-api-key", mock_session
        )

        assert len(commands) == 1
        _, _, _, cmd = commands[0]
        # Should fallback to resource region
        assert "--region" in cmd
        region_idx = cmd.index("--region")
        assert cmd[region_idx + 1] == "us-west-2"

    def test_creates_session_if_none_provided(self, sample_source_same_region):
        """Test that function creates a session if none is provided."""
        with patch("edot_discovery.cli.boto3.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_s3_client = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.client.return_value = mock_s3_client
            mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

            commands = generate_deployment_commands(
                [sample_source_same_region], "https://example.com", "test-api-key"
            )

            assert len(commands) == 1
            mock_session_class.assert_called_once()

    def test_all_log_types_have_correct_display_names(self, mock_session):
        """Test that all log types have correct display names."""
        log_types = [
            ("vpc_flow_logs", "VPC Flow Logs"),
            ("elb_access_logs", "ELB Access Logs"),
            ("cloudtrail", "CloudTrail"),
            ("waf", "AWS WAF"),
        ]
        mock_s3_client = MagicMock()
        mock_session.client.return_value = mock_s3_client
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "us-east-1"}

        for log_type, expected_display in log_types:
            source = LogSource(
                log_type=log_type,
                display_type=expected_display,
                source_id="test-id",
                resource_id="test-resource",
                destination=f"s3://bucket-{log_type}/",
                bucket_arn=f"arn:aws:s3:::bucket-{log_type}",
                region="us-east-1",
            )
            commands = generate_deployment_commands(
                [source], "https://example.com", "test-api-key", mock_session
            )
            assert len(commands) == 1
            display_name, _, _, _ = commands[0]
            assert display_name == expected_display
