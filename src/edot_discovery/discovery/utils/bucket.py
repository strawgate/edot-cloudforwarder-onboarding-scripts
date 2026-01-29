"""S3 bucket utilities."""

import boto3
from botocore.exceptions import ClientError

from edot_discovery.discovery.utils.console import warning


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
        warning(f"Could not determine region for bucket {bucket_arn}: {e}")
        return None
    except Exception as e:
        warning(f"Error getting bucket region for {bucket_arn}: {e}")
        return None
