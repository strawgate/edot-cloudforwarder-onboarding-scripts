"""ELB Access Logs discovery (ALB, NLB, Classic ELB)."""

import boto3
from botocore.exceptions import ClientError

from edot_discovery.discovery.types import LogSource
from edot_discovery.discovery.utils.console import warning


def discover_elb_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover ELB/ALB/NLB Access Logs writing to S3."""
    sources: list[LogSource] = []

    # Discover ALB/NLB via elbv2
    sources.extend(_discover_elbv2_logs(session, region))

    # Discover Classic ELB via elb
    sources.extend(_discover_classic_elb_logs(session, region))

    return sources


def _discover_elbv2_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover ALB/NLB Access Logs."""
    sources: list[LogSource] = []

    try:
        elbv2 = session.client("elbv2", region_name=region)
        paginator = elbv2.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                try:
                    attrs_response = elbv2.describe_load_balancer_attributes(
                        LoadBalancerArn=lb["LoadBalancerArn"]
                    )
                    config = {a["Key"]: a["Value"] for a in attrs_response.get("Attributes", [])}

                    if config.get("access_logs.s3.enabled") == "true":
                        bucket = config.get("access_logs.s3.bucket", "")

                        # Skip if bucket is empty
                        if not bucket:
                            warning(
                                f"{lb['LoadBalancerName']} in {region} has access logging "
                                "enabled but no S3 bucket configured, skipping"
                            )
                            continue

                        prefix = config.get("access_logs.s3.prefix", "")
                        destination = f"s3://{bucket}/{prefix}".rstrip("/")

                        lb_type = lb.get("Type", "application").upper()
                        sources.append(
                            LogSource(
                                log_type="elb_access_logs",
                                display_type=f"{lb_type} Access Logs",
                                source_id=lb["LoadBalancerName"],
                                resource_id=lb["LoadBalancerArn"],
                                destination=destination,
                                bucket_arn=f"arn:aws:s3:::{bucket}",
                                region=region,
                            )
                        )
                except ClientError as e:
                    warning(f"Could not get attributes for {lb['LoadBalancerName']}: {e}")
    except ClientError as e:
        warning(f"Could not describe ALB/NLB: {e}")
    except Exception as e:
        warning(f"Error discovering ALB/NLB logs: {e}")

    return sources


def _discover_classic_elb_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover Classic ELB Access Logs."""
    sources: list[LogSource] = []

    try:
        elb = session.client("elb", region_name=region)
        paginator = elb.get_paginator("describe_load_balancers")

        for page in paginator.paginate():
            for lb in page.get("LoadBalancerDescriptions", []):
                try:
                    attrs_response = elb.describe_load_balancer_attributes(
                        LoadBalancerName=lb["LoadBalancerName"]
                    )
                    access_log = attrs_response.get("LoadBalancerAttributes", {}).get(
                        "AccessLog", {}
                    )

                    if access_log.get("Enabled"):
                        bucket = access_log.get("S3BucketName", "")

                        # Skip if bucket is empty
                        if not bucket:
                            warning(
                                f"Classic ELB {lb['LoadBalancerName']} in {region} has access "
                                "logging enabled but no S3 bucket configured, skipping"
                            )
                            continue

                        prefix = access_log.get("S3BucketPrefix", "")
                        destination = f"s3://{bucket}/{prefix}".rstrip("/")

                        sources.append(
                            LogSource(
                                log_type="elb_access_logs",
                                display_type="Classic ELB Access Logs",
                                source_id=lb["LoadBalancerName"],
                                resource_id=lb["LoadBalancerName"],
                                destination=destination,
                                bucket_arn=f"arn:aws:s3:::{bucket}",
                                region=region,
                            )
                        )
                except ClientError as e:
                    warning(
                        f"Could not get attributes for Classic ELB {lb['LoadBalancerName']}: {e}"
                    )
    except ClientError as e:
        # Classic ELB API may not be available in all regions
        if "is not supported in this region" not in str(e):
            warning(f"Could not describe Classic ELB: {e}")
    except Exception as e:
        warning(f"Error discovering Classic ELB logs: {e}")

    return sources
