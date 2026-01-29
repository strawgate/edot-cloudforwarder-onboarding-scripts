"""Existing EDOT Cloud Forwarder stack detection."""

from typing import Literal

import boto3
from botocore.exceptions import ClientError

from edot_discovery.discovery.types import ExistingForwarder
from edot_discovery.discovery.utils.console import warning

# Reverse mapping: CloudFormation log type -> internal log_type
CF_TO_INTERNAL_LOG_TYPE = {
    "vpcflow": "vpc_flow_logs",
    "elbaccess": "elb_access_logs",
    "cloudtrail": "cloudtrail",
    "waf": "waf",
}

# Stack status type for CloudFormation
StackStatusType = Literal[
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_COMPLETE",
]


def get_existing_forwarders(
    session: boto3.Session, region: str
) -> dict[tuple[str, str], ExistingForwarder]:
    """
    Find existing EDOT Cloud Forwarder stacks in the region.

    Returns a dict mapping (bucket_arn, internal_log_type) to ExistingForwarder info.
    Only returns stacks in a "healthy" state (CREATE_COMPLETE, UPDATE_COMPLETE, etc.)
    """
    forwarders: dict[tuple[str, str], ExistingForwarder] = {}

    # Stack statuses that indicate a working forwarder
    healthy_statuses: list[StackStatusType] = [
        "CREATE_COMPLETE",
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "IMPORT_COMPLETE",
    ]

    try:
        cfn = session.client("cloudformation", region_name=region)

        # List all stacks (paginate manually since list_stacks doesn't have a paginator)
        next_token: str | None = None
        while True:
            if next_token:
                response = cfn.list_stacks(
                    StackStatusFilter=healthy_statuses,
                    NextToken=next_token,
                )
            else:
                response = cfn.list_stacks(StackStatusFilter=healthy_statuses)

            for stack_summary in response.get("StackSummaries", []):
                stack_name = stack_summary.get("StackName", "")

                # Only process stacks matching our naming pattern
                if not stack_name.startswith("edot-cf-"):
                    continue

                stack_status = stack_summary.get("StackStatus", "")

                try:
                    # Get stack details to extract parameters
                    stack_response = cfn.describe_stacks(StackName=stack_name)
                    stacks = stack_response.get("Stacks", [])
                    if not stacks:
                        continue

                    stack = stacks[0]
                    params = {
                        p["ParameterKey"]: p.get("ParameterValue", "")
                        for p in stack.get("Parameters", [])
                    }

                    bucket_arn = params.get("SourceS3BucketARN", "")
                    cf_log_type = params.get("EdotCloudForwarderS3LogsType", "")
                    otlp_endpoint = params.get("OTLPEndpoint", "")

                    if not bucket_arn or not cf_log_type:
                        continue

                    # Convert CF log type to internal log type
                    internal_log_type = CF_TO_INTERNAL_LOG_TYPE.get(cf_log_type)
                    if not internal_log_type:
                        continue

                    forwarder = ExistingForwarder(
                        stack_name=stack_name,
                        stack_status=stack_status,
                        otlp_endpoint=otlp_endpoint,
                        bucket_arn=bucket_arn,
                        log_type=cf_log_type,
                    )

                    forwarders[(bucket_arn, internal_log_type)] = forwarder

                except ClientError as e:
                    warning(f"Could not describe stack {stack_name}: {e}")

            next_token = response.get("NextToken")
            if not next_token:
                break

    except ClientError as e:
        warning(f"Could not list CloudFormation stacks: {e}")
    except Exception as e:
        warning(f"Error checking existing forwarders: {e}")

    return forwarders
