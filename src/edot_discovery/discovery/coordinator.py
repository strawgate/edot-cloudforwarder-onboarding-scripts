"""Discovery coordinator - orchestrates discovery of all log sources."""

import boto3
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from edot_discovery.discovery.services.cloudtrail import discover_cloudtrail
from edot_discovery.discovery.services.elb_logs import discover_elb_logs
from edot_discovery.discovery.services.flow_logs import discover_flow_logs
from edot_discovery.discovery.services.waf_logs import discover_waf_logs
from edot_discovery.discovery.stacks.forwarders import get_existing_forwarders
from edot_discovery.discovery.types import LogSource

# Console for progress display
_console = Console()


def discover_all_sources(region: str) -> list[LogSource]:
    """Discover all log sources in the specified region."""
    session = boto3.Session(region_name=region)
    all_sources: list[LogSource] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=_console,
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
