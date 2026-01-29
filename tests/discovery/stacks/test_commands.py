"""Tests for edot_discovery.discovery.stacks.commands."""

import pytest
from inline_snapshot import snapshot

from edot_discovery.discovery.stacks.commands import generate_deployment_commands
from edot_discovery.discovery.types import LogSource

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def vpc_flow_log_source() -> LogSource:
    """Create a sample VPC Flow Log source."""
    return LogSource(
        log_type="vpc_flow_logs",
        display_type="VPC Flow Logs",
        source_id="fl-abc123",
        resource_id="vpc-xyz789",
        destination="s3://my-bucket/logs/",
        bucket_arn="arn:aws:s3:::my-bucket",
        region="us-east-1",
        bucket_region="eu-west-1",
    )


@pytest.fixture
def elb_access_log_source() -> LogSource:
    """Create a sample ELB Access Log source."""
    return LogSource(
        log_type="elb_access_logs",
        display_type="ALB Access Logs",
        source_id="my-alb",
        resource_id="arn:aws:elasticloadbalancing:us-west-2:123:loadbalancer/app/my-alb/abc",
        destination="s3://my-bucket/alb/",
        bucket_arn="arn:aws:s3:::my-bucket",
        region="us-west-2",
        bucket_region="us-east-1",
    )


@pytest.fixture
def source_with_unknown_bucket_region() -> LogSource:
    """Create a source where bucket region is unknown."""
    return LogSource(
        log_type="vpc_flow_logs",
        display_type="VPC Flow Logs",
        source_id="fl-unknown",
        resource_id="vpc-unknown",
        destination="s3://deleted-bucket/logs/",
        bucket_arn="arn:aws:s3:::deleted-bucket",
        region="us-west-2",
        bucket_region=None,
    )


# =============================================================================
# Tests
# =============================================================================


class TestGenerateDeploymentCommands:
    """Tests for generate_deployment_commands function."""

    def test_generates_single_command(self, vpc_flow_log_source: LogSource):
        """Test generating a single deployment command."""
        commands = generate_deployment_commands(
            [vpc_flow_log_source], "https://example.com", "test-api-key"
        )

        assert len(commands) == 1
        display_name, bucket_arn, bucket_region, log_type, cmd = commands[0]

        assert (display_name, bucket_arn, bucket_region, log_type) == snapshot(
            ("VPC Flow Logs", "arn:aws:s3:::my-bucket", "eu-west-1", "vpc_flow_logs")
        )
        assert cmd == snapshot(
            [
                "aws",
                "cloudformation",
                "create-stack",
                "--stack-name",
                "edot-cf-vpcflow-my-bucket",
                "--template-url",
                "https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml",
                "--capabilities",
                "CAPABILITY_NAMED_IAM",
                "CAPABILITY_AUTO_EXPAND",
                "--region",
                "eu-west-1",
                "--parameters",
                "ParameterKey=OTLPEndpoint,ParameterValue=https://example.com",
                "ParameterKey=ElasticAPIKey,ParameterValue=test-api-key",
                "ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue=vpcflow",
                "ParameterKey=SourceS3BucketARN,ParameterValue=arn:aws:s3:::my-bucket",
            ]
        )

    def test_uses_bucket_region_not_resource_region(self, elb_access_log_source: LogSource):
        """Test that deployment uses bucket region, not resource region."""
        commands = generate_deployment_commands(
            [elb_access_log_source], "https://example.com", "test-api-key"
        )

        assert len(commands) == 1
        _, _, bucket_region, _, cmd = commands[0]

        # Resource is in us-west-2, but bucket is in us-east-1
        assert bucket_region == snapshot("us-east-1")
        assert cmd[cmd.index("--region") + 1] == "us-east-1"

    def test_falls_back_to_resource_region_when_bucket_region_unknown(
        self, source_with_unknown_bucket_region: LogSource
    ):
        """Test fallback to resource region when bucket region is None."""
        commands = generate_deployment_commands(
            [source_with_unknown_bucket_region], "https://example.com", "test-api-key"
        )

        assert len(commands) == 1
        _, _, bucket_region, _, cmd = commands[0]

        assert bucket_region == snapshot("us-west-2")
        assert cmd[cmd.index("--region") + 1] == "us-west-2"

    def test_groups_multiple_sources_same_bucket_and_type(self):
        """Test that multiple sources with same bucket+type generate one command."""
        source1 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://shared-bucket/vpc/",
            bucket_arn="arn:aws:s3:::shared-bucket",
            region="us-east-1",
            bucket_region="eu-west-1",
        )
        source2 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-2",
            resource_id="vpc-2",
            destination="s3://shared-bucket/vpc/",
            bucket_arn="arn:aws:s3:::shared-bucket",
            region="us-west-2",
            bucket_region="eu-west-1",
        )

        commands = generate_deployment_commands(
            [source1, source2], "https://example.com", "test-api-key"
        )

        assert len(commands) == snapshot(1)

    def test_different_buckets_generate_separate_commands(self):
        """Test that different buckets generate separate commands."""
        source1 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://bucket-1/vpc/",
            bucket_arn="arn:aws:s3:::bucket-1",
            region="us-east-1",
            bucket_region="us-east-1",
        )
        source2 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-2",
            resource_id="vpc-2",
            destination="s3://bucket-2/vpc/",
            bucket_arn="arn:aws:s3:::bucket-2",
            region="us-east-1",
            bucket_region="us-west-2",
        )

        commands = generate_deployment_commands(
            [source1, source2], "https://example.com", "test-api-key"
        )

        assert len(commands) == snapshot(2)

        bucket_arns = {cmd[1] for cmd in commands}
        assert bucket_arns == snapshot({"arn:aws:s3:::bucket-1", "arn:aws:s3:::bucket-2"})

    def test_different_log_types_same_bucket_generate_separate_commands(self):
        """Test that different log types for same bucket generate separate commands."""
        source1 = LogSource(
            log_type="vpc_flow_logs",
            display_type="VPC Flow Logs",
            source_id="fl-1",
            resource_id="vpc-1",
            destination="s3://my-bucket/vpc/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-east-1",
            bucket_region="us-east-1",
        )
        source2 = LogSource(
            log_type="elb_access_logs",
            display_type="ELB Access Logs",
            source_id="alb-1",
            resource_id="arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/alb/abc",
            destination="s3://my-bucket/alb/",
            bucket_arn="arn:aws:s3:::my-bucket",
            region="us-east-1",
            bucket_region="us-east-1",
        )

        commands = generate_deployment_commands(
            [source1, source2], "https://example.com", "test-api-key"
        )

        assert len(commands) == snapshot(2)

        log_types = {cmd[3] for cmd in commands}
        assert log_types == snapshot({"vpc_flow_logs", "elb_access_logs"})

    @pytest.mark.parametrize(
        ("log_type", "expected_display_name"),
        [
            ("vpc_flow_logs", "VPC Flow Logs"),
            ("elb_access_logs", "ELB Access Logs"),
            ("cloudtrail", "CloudTrail"),
            ("waf", "AWS WAF"),
        ],
    )
    def test_display_names_for_all_log_types(self, log_type: str, expected_display_name: str):
        """Test that all log types have correct display names."""
        source = LogSource(
            log_type=log_type,
            display_type=expected_display_name,
            source_id="test-id",
            resource_id="test-resource",
            destination=f"s3://bucket-{log_type}/",
            bucket_arn=f"arn:aws:s3:::bucket-{log_type}",
            region="us-east-1",
            bucket_region="us-east-1",
        )

        commands = generate_deployment_commands([source], "https://example.com", "test-api-key")

        assert len(commands) == 1
        display_name = commands[0][0]
        assert display_name == expected_display_name
