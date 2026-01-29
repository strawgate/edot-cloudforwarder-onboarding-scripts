"""Tests for edot_discovery.discovery.utils.cloudformation."""

import pytest
from inline_snapshot import snapshot

from edot_discovery.discovery.utils.cloudformation import (
    LOG_TYPE_MAP,
    generate_cloudformation_command,
    generate_stack_name,
    redact_command_for_display,
)

# =============================================================================
# Tests for generate_stack_name
# =============================================================================


class TestGenerateStackName:
    """Tests for generate_stack_name function."""

    @pytest.mark.parametrize(
        ("bucket_arn", "log_type", "expected"),
        [
            ("arn:aws:s3:::my-vpc-logs", "vpc_flow_logs", "edot-cf-vpcflow-my-vpc-logs"),
            ("arn:aws:s3:::my-elb-logs", "elb_access_logs", "edot-cf-elbaccess-my-elb-logs"),
            ("arn:aws:s3:::my-trail-logs", "cloudtrail", "edot-cf-cloudtrail-my-trail-logs"),
            ("arn:aws:s3:::my-waf-logs", "waf", "edot-cf-waf-my-waf-logs"),
        ],
    )
    def test_generates_expected_stack_names(self, bucket_arn: str, log_type: str, expected: str):
        """Test stack name generation for different log types."""
        result = generate_stack_name(bucket_arn, log_type)
        assert result == expected
        assert result[0].isalpha()
        assert len(result) <= 128

    def test_sanitizes_special_characters(self):
        """Test that special characters are replaced with hyphens."""
        result = generate_stack_name("arn:aws:s3:::my.bucket_name", "vpc_flow_logs")

        assert result == snapshot("edot-cf-vpcflow-my-bucket-name")
        assert "." not in result
        assert "_" not in result

    def test_handles_numeric_start(self):
        """Test that bucket names starting with numbers are handled."""
        result = generate_stack_name("arn:aws:s3:::123-bucket", "vpc_flow_logs")

        assert result == snapshot("edot-cf-vpcflow-123-bucket")
        assert result[0].isalpha()

    def test_truncates_long_names_with_hash(self):
        """Test that long names are truncated with hash for uniqueness."""
        bucket_arn = "arn:aws:s3:::" + "a" * 150
        result = generate_stack_name(bucket_arn, "vpc_flow_logs")

        assert len(result) <= 128
        assert result[0].isalpha()
        # Should contain a hash suffix
        assert "-" in result[-9:]  # Hash is 8 chars + hyphen

    def test_is_deterministic(self):
        """Test that same inputs always produce same output."""
        bucket_arn = "arn:aws:s3:::my-logs"
        log_type = "vpc_flow_logs"

        results = [generate_stack_name(bucket_arn, log_type) for _ in range(3)]

        assert len(set(results)) == 1


# =============================================================================
# Tests for generate_cloudformation_command
# =============================================================================


class TestGenerateCloudformationCommand:
    """Tests for generate_cloudformation_command function."""

    def test_vpc_flow_logs_command(self):
        """Test command generation for VPC flow logs."""
        result = generate_cloudformation_command(
            stack_name="test-stack",
            log_type="vpc_flow_logs",
            bucket_arn="arn:aws:s3:::my-bucket",
            otlp_endpoint="https://example.com",
            api_key="test-key",
            region="us-east-1",
        )

        assert result == snapshot(
            [
                "aws",
                "cloudformation",
                "create-stack",
                "--stack-name",
                "test-stack",
                "--template-url",
                "https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml",
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
                "--region",
                "us-east-1",
                "--parameters",
                "ParameterKey=OTLPEndpoint,ParameterValue=https://example.com",
                "ParameterKey=ElasticAPIKey,ParameterValue=test-key",
                "ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue=vpcflow",
                "ParameterKey=SourceS3BucketARN,ParameterValue=arn:aws:s3:::my-bucket",
            ]
        )

    def test_elb_access_logs_command(self):
        """Test command generation for ELB access logs."""
        result = generate_cloudformation_command(
            stack_name="elb-stack",
            log_type="elb_access_logs",
            bucket_arn="arn:aws:s3:::elb-logs",
            otlp_endpoint="https://elastic.example.com",
            api_key="secret-key",
            region="eu-west-1",
        )

        assert result == snapshot(
            [
                "aws",
                "cloudformation",
                "create-stack",
                "--stack-name",
                "elb-stack",
                "--template-url",
                "https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml",
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
                "--region",
                "eu-west-1",
                "--parameters",
                "ParameterKey=OTLPEndpoint,ParameterValue=https://elastic.example.com",
                "ParameterKey=ElasticAPIKey,ParameterValue=secret-key",
                "ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue=elbaccess",
                "ParameterKey=SourceS3BucketARN,ParameterValue=arn:aws:s3:::elb-logs",
            ]
        )

    def test_cloudtrail_command(self):
        """Test command generation for CloudTrail."""
        result = generate_cloudformation_command(
            stack_name="trail-stack",
            log_type="cloudtrail",
            bucket_arn="arn:aws:s3:::trail-logs",
            otlp_endpoint="https://elastic.example.com",
            api_key="api-key",
            region="us-west-2",
        )

        assert result == snapshot(
            [
                "aws",
                "cloudformation",
                "create-stack",
                "--stack-name",
                "trail-stack",
                "--template-url",
                "https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml",
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
                "--region",
                "us-west-2",
                "--parameters",
                "ParameterKey=OTLPEndpoint,ParameterValue=https://elastic.example.com",
                "ParameterKey=ElasticAPIKey,ParameterValue=api-key",
                "ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue=cloudtrail",
                "ParameterKey=SourceS3BucketARN,ParameterValue=arn:aws:s3:::trail-logs",
            ]
        )

    def test_waf_command(self):
        """Test command generation for WAF logs."""
        result = generate_cloudformation_command(
            stack_name="waf-stack",
            log_type="waf",
            bucket_arn="arn:aws:s3:::waf-logs",
            otlp_endpoint="https://elastic.example.com",
            api_key="waf-key",
            region="ap-northeast-1",
        )

        assert result == snapshot(
            [
                "aws",
                "cloudformation",
                "create-stack",
                "--stack-name",
                "waf-stack",
                "--template-url",
                "https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml",
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
                "--region",
                "ap-northeast-1",
                "--parameters",
                "ParameterKey=OTLPEndpoint,ParameterValue=https://elastic.example.com",
                "ParameterKey=ElasticAPIKey,ParameterValue=waf-key",
                "ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue=waf",
                "ParameterKey=SourceS3BucketARN,ParameterValue=arn:aws:s3:::waf-logs",
            ]
        )


# =============================================================================
# Tests for redact_command_for_display
# =============================================================================


class TestRedactCommandForDisplay:
    """Tests for redact_command_for_display function."""

    def test_redacts_elastic_api_key_parameter(self):
        """Test that ElasticAPIKey parameter value is redacted."""
        cmd = [
            "aws",
            "cloudformation",
            "create-stack",
            "--stack-name",
            "my-stack",
            "ParameterKey=ElasticAPIKey,ParameterValue=super-secret-key-12345",
            "ParameterKey=OTLPEndpoint,ParameterValue=https://example.com",
        ]

        result = redact_command_for_display(cmd)

        assert "super-secret-key-12345" not in result
        assert result == snapshot(
            "aws cloudformation create-stack --stack-name my-stack "
            "'ParameterKey=ElasticAPIKey,ParameterValue=<REDACTED>' "
            "ParameterKey=OTLPEndpoint,ParameterValue=https://example.com"
        )

    @pytest.mark.parametrize(
        "key_pattern",
        ["API_KEY=secret", "APIKEY=secret", "api_key=secret", "apikey=secret"],
    )
    def test_redacts_common_api_key_patterns(self, key_pattern: str):
        """Test that common API key environment variable patterns are redacted."""
        cmd = ["aws", "cloudformation", key_pattern]

        result = redact_command_for_display(cmd)

        assert "secret" not in result
        assert "<REDACTED>" in result


# =============================================================================
# Tests for LOG_TYPE_MAP
# =============================================================================


class TestLogTypeMap:
    """Tests for LOG_TYPE_MAP constant."""

    def test_all_mappings(self):
        """Test all log type mappings."""
        assert LOG_TYPE_MAP == snapshot(
            {
                "vpc_flow_logs": "vpcflow",
                "elb_access_logs": "elbaccess",
                "cloudtrail": "cloudtrail",
                "waf": "waf",
            }
        )
