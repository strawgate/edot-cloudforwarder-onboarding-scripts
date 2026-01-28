"""AWS WAF logs discovery."""

import boto3
from botocore.exceptions import ClientError

from .types import LogSource
from .utils import warn


def discover_waf_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover AWS WAF Web ACLs with logging to S3."""
    sources: list[LogSource] = []

    # WAFv2 has two scopes: REGIONAL and CLOUDFRONT
    # CLOUDFRONT scope is only available in us-east-1
    scopes = ["REGIONAL"]
    if region == "us-east-1":
        scopes.append("CLOUDFRONT")

    # Create wafv2 client once outside the loop
    wafv2 = session.client("wafv2", region_name=region)

    for scope in scopes:
        try:
            # List all Web ACLs for this scope using manual pagination
            # (list_web_acls doesn't support boto3 paginators)
            next_marker: str | None = None
            while True:
                if next_marker:
                    response = wafv2.list_web_acls(Scope=scope, NextMarker=next_marker)
                else:
                    response = wafv2.list_web_acls(Scope=scope)

                for acl in response.get("WebACLs", []):
                    acl_arn = acl.get("ARN", "")
                    acl_name = acl.get("Name", "unknown")

                    try:
                        # Get logging configuration for this Web ACL
                        logging_config = wafv2.get_logging_configuration(ResourceArn=acl_arn)

                        log_destinations = logging_config.get("LoggingConfiguration", {}).get(
                            "LogDestinationConfigs", []
                        )

                        for dest_arn in log_destinations:
                            # Only include S3 destinations
                            # S3 ARN format: arn:aws:s3:::bucket-name
                            if dest_arn.startswith("arn:aws:s3:::"):
                                bucket_name = dest_arn.replace("arn:aws:s3:::", "")

                                # Determine display type based on scope
                                if scope == "CLOUDFRONT":
                                    display_type = "WAF (CloudFront)"
                                else:
                                    display_type = "WAF (Regional)"

                                sources.append(
                                    LogSource(
                                        log_type="waf",
                                        display_type=display_type,
                                        source_id=acl_name,
                                        resource_id=acl_arn,
                                        destination=f"s3://{bucket_name}",
                                        bucket_arn=dest_arn,
                                        region=region,
                                    )
                                )
                    except ClientError as e:
                        # WAFNonexistentItemException means no logging configured
                        if "WAFNonexistentItemException" not in str(e):
                            warn(f"Could not get logging config for {acl_name}: {e}")

                # Check for more results
                next_marker = response.get("NextMarker")
                if not next_marker:
                    break
        except ClientError as e:
            warn(f"Could not list WAF Web ACLs ({scope}): {e}")
        except Exception as e:
            warn(f"Error discovering WAF logs ({scope}): {e}")

    return sources
