"""VPC Flow Logs discovery."""

import boto3
from botocore.exceptions import ClientError

from .types import LogSource
from .utils import extract_bucket_arn, warn


def discover_flow_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover VPC Flow Logs writing to S3."""
    sources: list[LogSource] = []
    try:
        ec2 = session.client("ec2", region_name=region)
        paginator = ec2.get_paginator("describe_flow_logs")

        for page in paginator.paginate():
            for fl in page.get("FlowLogs", []):
                # Only include active flow logs writing to S3
                if fl.get("LogDestinationType") == "s3" and fl.get("FlowLogStatus") == "ACTIVE":
                    destination = fl.get("LogDestination", "")
                    sources.append(
                        LogSource(
                            log_type="vpc_flow_logs",
                            display_type="VPC Flow Logs",
                            source_id=fl["FlowLogId"],
                            resource_id=fl.get("ResourceId", "unknown"),
                            destination=destination,
                            bucket_arn=extract_bucket_arn(destination),
                            region=region,
                        )
                    )
    except ClientError as e:
        warn(f"Could not describe flow logs: {e}")
    except Exception as e:
        warn(f"Error discovering flow logs: {e}")

    return sources
