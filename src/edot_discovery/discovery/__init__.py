"""
AWS Log Source Discovery Module.

Discovers AWS log sources (VPC Flow Logs, ELB Access Logs, CloudTrail, WAF)
that are writing to S3 buckets.
"""

import boto3
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .cloudtrail import discover_cloudtrail
from .elb_logs import discover_elb_logs
from .flow_logs import discover_flow_logs
from .forwarders import get_existing_forwarders
from .types import ExistingForwarder, LogSource
from .waf_logs import discover_waf_logs

# Re-export types
__all__ = [
    "LogSource",
    "ExistingForwarder",
    "discover_all_sources",
    "discover_flow_logs",
    "discover_elb_logs",
    "discover_cloudtrail",
    "discover_waf_logs",
    "get_existing_forwarders",
]

# Console for progress display
console = Console()


def discover_all_sources(region: str) -> list[LogSource]:
    """Discover all log sources in the specified region."""
    session = boto3.Session(region_name=region)
    all_sources: list[LogSource] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("Discovering log sources...", total=None)

        progress.update(task, description="Scanning VPC Flow Logs...")
        all_sources.extend(discover_flow_logs(session, region))

        progress.update(task, description="Scanning ELB Access Logs...")
        all_sources.extend(discover_elb_logs(session, region))

        progress.update(task, description="Scanning CloudTrail trails...")
        all_sources.extend(discover_cloudtrail(session, region))

        progress.update(task, description="Scanning WAF Web ACLs...")
        all_sources.extend(discover_waf_logs(session, region))

        progress.update(task, description="Checking existing EDOT forwarders...")
        existing_forwarders = get_existing_forwarders(session, region)

    # Annotate sources with existing forwarder info
    for source in all_sources:
        key = (source.bucket_arn, source.log_type)
        if key in existing_forwarders:
            source.existing_forwarder = existing_forwarders[key]

    return all_sources
