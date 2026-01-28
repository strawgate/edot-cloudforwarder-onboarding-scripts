"""Shared utilities for log source discovery."""

import hashlib
import re
import shlex
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError
from rich.console import Console

# Shared console for warning messages
console = Console()

# CloudFormation template URL
CLOUDFORMATION_TEMPLATE_URL = (
    "https://edot-cloud-forwarder.s3.amazonaws.com/"
    "v0/latest/cloudformation/s3_logs-cloudformation.yaml"
)

# Map internal log_type to CloudFormation EdotCloudForwarderS3LogsType values
LOG_TYPE_MAP = {
    "vpc_flow_logs": "vpcflow",
    "elb_access_logs": "elbaccess",
    "cloudtrail": "cloudtrail",
    "waf": "waf",
}


def extract_bucket_arn(destination: str) -> str:
    """Extract the bucket ARN from a full S3 destination."""
    # Handle ARN format: arn:aws:s3:::bucket-name/prefix/
    if destination.startswith("arn:aws:s3:::"):
        bucket_part = destination.replace("arn:aws:s3:::", "")
        bucket_name = bucket_part.split("/")[0]
        return f"arn:aws:s3:::{bucket_name}"
    # Handle s3:// format
    elif destination.startswith("s3://"):
        bucket_name = destination.replace("s3://", "").split("/")[0]
        return f"arn:aws:s3:::{bucket_name}"
    return destination


def warn(message: str) -> None:
    """Print a warning message to the console."""
    console.print(f"[yellow]Warning: {message}[/yellow]")


# Console print helpers for consistent styling
def success(message: str) -> None:
    """Print a success message in green."""
    console.print(f"[green]{message}[/green]")


def error(message: str) -> None:
    """Print an error message in red."""
    console.print(f"[red]{message}[/red]")


def warning(message: str) -> None:
    """Print a warning message in yellow."""
    console.print(f"[yellow]{message}[/yellow]")


def dim(message: str) -> None:
    """Print a dimmed/secondary message."""
    console.print(f"[dim]{message}[/dim]")


def bold(message: str) -> None:
    """Print a bold message."""
    console.print(f"[bold]{message}[/bold]")


def cancel(message: str) -> None:
    """Print a cancellation message in yellow."""
    console.print(f"[yellow]{message}[/yellow]")


def get_default_region() -> str:
    """Get the default AWS region from boto3 session or environment."""
    session = boto3.Session()
    return session.region_name or "us-east-1"


def get_enabled_regions(default_region: str) -> list[str]:
    """
    Get list of enabled AWS regions for the account.

    Returns regions sorted with default_region first, then alphabetically.
    """
    try:
        ec2 = boto3.client("ec2", region_name=default_region)
        response = ec2.describe_regions(
            Filters=[{"Name": "opt-in-status", "Values": ["opt-in-not-required", "opted-in"]}]
        )
        regions = [r["RegionName"] for r in response.get("Regions", [])]

        # Sort alphabetically, but put default region first
        regions.sort()
        if default_region in regions:
            regions.remove(default_region)
            regions.insert(0, default_region)

        return regions
    except ClientError as e:
        warn(f"Could not list regions: {e}")
        # Fallback to common regions
        return [default_region]
    except Exception as e:
        warn(f"Error listing regions: {e}")
        return [default_region]


def get_bucket_region(bucket_arn: str, session: boto3.Session | None = None) -> str | None:
    """
    Get the actual AWS region of an S3 bucket.

    Note: AWS services (VPC Flow Logs, ELB, CloudTrail, WAF) CAN write to S3 buckets
    cross-region. However, S3 bucket notifications (Lambda triggers) MUST be in the
    same region as the bucket. This function ensures we deploy the CloudFormation stack
    (and its Lambda functions) in the bucket's region, not the resource's region.

    Args:
        bucket_arn: The ARN of the S3 bucket
        session: Optional boto3 Session. If not provided, creates a new session.

    Returns:
        The bucket region, or None if unable to determine.
    """
    if session is None:
        session = boto3.Session()

    try:
        # Extract bucket name from ARN
        bucket_name = bucket_arn.replace("arn:aws:s3:::", "")

        # S3 get_bucket_location can be called from any region
        s3 = session.client("s3")
        response = s3.get_bucket_location(Bucket=bucket_name)

        # get_bucket_location returns None for us-east-1 (the default)
        location = response.get("LocationConstraint")
        if location is None:
            return "us-east-1"
        return location
    except ClientError as e:
        warn(f"Could not determine region for bucket {bucket_arn}: {e}")
        return None
    except Exception as e:
        warn(f"Error getting bucket region for {bucket_arn}: {e}")
        return None


def generate_stack_name(bucket_arn: str, log_type: str) -> str:
    """
    Generate a deterministic, idempotent CloudFormation stack name.

    Stack names must:
    - Start with a letter
    - Contain only alphanumeric characters and hyphens
    - Be <= 128 characters
    """
    # Extract bucket name from ARN
    bucket_name = bucket_arn.replace("arn:aws:s3:::", "")

    # Create base name
    cf_log_type = LOG_TYPE_MAP.get(log_type, log_type)
    base_name = f"edot-cf-{cf_log_type}-{bucket_name}"

    # Sanitize: keep only alphanumeric and hyphens, ensure starts with letter
    sanitized = re.sub(r"[^a-zA-Z0-9-]", "-", base_name)
    sanitized = re.sub(r"-+", "-", sanitized)  # Collapse multiple hyphens
    sanitized = sanitized.strip("-")

    # Handle empty result (edge case: bucket name was all special chars)
    if not sanitized:
        sanitized = "bucket"

    # Ensure starts with a letter
    if not sanitized[0].isalpha():
        sanitized = "s-" + sanitized

    # If too long, truncate and add hash for uniqueness
    max_len = 128
    if len(sanitized) > max_len:
        # Create a short hash of the full identifier
        full_id = f"{bucket_arn}-{log_type}"
        hash_suffix = hashlib.sha256(full_id.encode()).hexdigest()[:8]
        # Truncate base and append hash
        truncate_len = max_len - len(hash_suffix) - 1  # -1 for hyphen
        sanitized = sanitized[:truncate_len].rstrip("-") + "-" + hash_suffix

    return sanitized


def generate_cloudformation_command(
    stack_name: str,
    log_type: str,
    bucket_arn: str,
    otlp_endpoint: str,
    api_key: str,
    region: str,
) -> list[str]:
    """
    Generate a CloudFormation create-stack command as an argv list.

    Returns a list suitable for subprocess.run with shell=False.
    """
    # Map to CloudFormation expected log type value
    cf_log_type = LOG_TYPE_MAP.get(log_type, log_type)

    return [
        "aws",
        "cloudformation",
        "create-stack",
        "--stack-name",
        stack_name,
        "--template-url",
        CLOUDFORMATION_TEMPLATE_URL,
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        "CAPABILITY_AUTO_EXPAND",
        "--region",
        region,
        "--parameters",
        f"ParameterKey=OTLPEndpoint,ParameterValue={otlp_endpoint}",
        f"ParameterKey=ElasticAPIKey,ParameterValue={api_key}",
        f"ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue={cf_log_type}",
        f"ParameterKey=SourceS3BucketARN,ParameterValue={bucket_arn}",
    ]


def redact_command_for_display(cmd: list[str]) -> str:
    """
    Convert command list to display string with sensitive values redacted.

    Redacts:
    - ElasticAPIKey parameter values
    - Common API key patterns
    """
    redacted_parts = []
    for part in cmd:
        # Redact ElasticAPIKey parameter
        if part.startswith("ParameterKey=ElasticAPIKey,ParameterValue="):
            redacted_parts.append("ParameterKey=ElasticAPIKey,ParameterValue=<REDACTED>")
        # Redact common API key patterns
        elif re.match(r"^(API_KEY|APIKEY|api_key|apikey)=", part):
            key_name = part.split("=")[0]
            redacted_parts.append(f"{key_name}=<REDACTED>")
        else:
            redacted_parts.append(part)

    return shlex.join(redacted_parts)


def validate_otlp_endpoint(endpoint: str | None) -> bool:
    """
    Validate OTLP endpoint format.

    Requirements:
    - Must be a valid URL
    - Must use HTTPS scheme
    - Must have a non-empty host with at least one dot (domain) or be localhost
    """
    if not endpoint:
        return False

    try:
        parsed = urlparse(endpoint)
    except Exception:
        return False

    # Must be HTTPS
    if parsed.scheme != "https":
        return False

    # Must have a host
    if not parsed.netloc:
        return False

    # Host must be a valid domain (contains dot) or localhost
    host = parsed.netloc.split(":")[0]  # Remove port if present
    if "." not in host and host != "localhost":
        return False

    return True
