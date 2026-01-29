"""AWS region utilities."""

import boto3
from botocore.exceptions import ClientError

from edot_discovery.discovery.utils.console import warning


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
        warning(f"Could not list regions: {e}")
        # Fallback to common regions
        return [default_region]
    except Exception as e:
        warning(f"Error listing regions: {e}")
        return [default_region]
