"""CloudFormation deployment command generation."""

from edot_discovery.discovery.types import LogSource
from edot_discovery.discovery.utils.cloudformation import (
    generate_cloudformation_command,
    generate_stack_name,
)
from edot_discovery.discovery.utils.console import warning


def generate_deployment_commands(
    selected_sources: list[LogSource],
    otlp_endpoint: str,
    api_key: str,
) -> list[tuple[str, str, str, str, list[str]]]:
    """
    Generate CloudFormation deployment commands for selected sources.

    This is a pure function with no side effects - it takes LogSource objects
    with pre-populated bucket_region and returns command tuples.

    Args:
        selected_sources: List of LogSource objects to generate commands for
        otlp_endpoint: OTLP endpoint URL for Elastic Cloud
        api_key: Elastic API key

    Returns:
        List of tuples: (display_name, bucket_arn, bucket_region, log_type, command_list)

    Note: One stack per unique bucket+log_type combination.
    Uses the bucket's actual region (looked up earlier) for deployment.
    """
    commands: list[tuple[str, str, str, str, list[str]]] = []

    # Group sources by (bucket_arn, log_type)
    buckets_by_type: dict[tuple[str, str], list[LogSource]] = {}
    for source in selected_sources:
        key = (source.bucket_arn, source.log_type)
        if key not in buckets_by_type:
            buckets_by_type[key] = []
        buckets_by_type[key].append(source)

    # Generate one command per unique bucket+type
    for (bucket_arn, log_type), sources in buckets_by_type.items():
        # Use pre-populated bucket_region, fallback to resource region if still unknown
        bucket_region = sources[0].bucket_region
        if bucket_region is None:
            bucket_region = sources[0].region
            warning(f"Using fallback region {bucket_region} for {bucket_arn}")

        # Generate deterministic stack name
        stack_name = generate_stack_name(bucket_arn, log_type)

        # Set display name based on log type
        if log_type == "vpc_flow_logs":
            display_name = "VPC Flow Logs"
        elif log_type == "cloudtrail":
            display_name = "CloudTrail"
        elif log_type == "waf":
            display_name = "AWS WAF"
        else:
            display_name = "ELB Access Logs"

        cmd = generate_cloudformation_command(
            stack_name=stack_name,
            log_type=log_type,
            bucket_arn=bucket_arn,
            otlp_endpoint=otlp_endpoint,
            api_key=api_key,
            region=bucket_region,
        )

        commands.append((display_name, bucket_arn, bucket_region, log_type, cmd))

    return commands
