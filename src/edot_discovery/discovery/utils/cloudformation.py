"""CloudFormation command generation utilities."""

import hashlib
import re
import shlex

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
