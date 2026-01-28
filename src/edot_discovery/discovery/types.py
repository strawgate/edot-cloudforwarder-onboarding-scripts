"""Shared types for log source discovery."""

from dataclasses import dataclass, field


@dataclass
class ExistingForwarder:
    """Information about an existing EDOT Cloud Forwarder stack."""

    stack_name: str
    stack_status: str  # e.g., CREATE_COMPLETE, UPDATE_COMPLETE
    otlp_endpoint: str
    bucket_arn: str
    log_type: str  # CloudFormation value: vpcflow, elbaccess, cloudtrail, waf


@dataclass
class LogSource:
    """Represents a discovered log source."""

    log_type: str  # 'vpc_flow_logs', 'elb_access_logs', 'cloudtrail', or 'waf'
    display_type: str  # Human-readable type
    source_id: str  # Flow log ID, LB name, Trail name, or Web ACL name
    resource_id: str  # VPC/Subnet/ENI ID, LB ARN, Trail ARN, or Web ACL ARN
    destination: str  # Full S3 destination path
    bucket_arn: str  # S3 bucket ARN (without path)
    region: str  # AWS region
    existing_forwarder: ExistingForwarder | None = field(default=None)
