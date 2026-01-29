"""CloudTrail discovery."""

import boto3
from botocore.exceptions import ClientError

from edot_discovery.discovery.types import LogSource
from edot_discovery.discovery.utils.console import warning


def discover_cloudtrail(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover CloudTrail trails writing to S3."""
    sources: list[LogSource] = []
    try:
        cloudtrail = session.client("cloudtrail", region_name=region)

        # Get all trails (including organization trails)
        response = cloudtrail.describe_trails(includeShadowTrails=False)

        for trail in response.get("trailList", []):
            # Only include trails that have S3 bucket configured
            bucket_name = trail.get("S3BucketName")
            if not bucket_name:
                continue

            # Check if this trail's home region matches our scan region
            # (trails can be multi-region but have a home region)
            trail_home_region = trail.get("HomeRegion", region)
            if trail_home_region != region:
                continue

            trail_name = trail.get("Name", "unknown")
            trail_arn = trail.get("TrailARN", "")
            s3_prefix = trail.get("S3KeyPrefix", "")

            # Build destination path
            if s3_prefix:
                destination = f"s3://{bucket_name}/{s3_prefix}"
            else:
                destination = f"s3://{bucket_name}"

            # Determine trail type for display
            is_org_trail = trail.get("IsOrganizationTrail", False)
            is_multi_region = trail.get("IsMultiRegionTrail", False)

            display_parts = ["CloudTrail"]
            if is_org_trail:
                display_parts.append("(Organization)")
            elif is_multi_region:
                display_parts.append("(Multi-Region)")

            sources.append(
                LogSource(
                    log_type="cloudtrail",
                    display_type=" ".join(display_parts),
                    source_id=trail_name,
                    resource_id=trail_arn,
                    destination=destination,
                    bucket_arn=f"arn:aws:s3:::{bucket_name}",
                    region=region,
                )
            )
    except ClientError as e:
        warning(f"Could not describe CloudTrail trails: {e}")
    except Exception as e:
        warning(f"Error discovering CloudTrail: {e}")

    return sources
