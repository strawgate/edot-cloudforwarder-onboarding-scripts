#!/usr/bin/env python3
"""
EDOT Cloud Forwarder - AWS Log Source Discovery & Onboarding Tool

This interactive tool discovers AWS log sources (VPC Flow Logs, ELB Access Logs,
CloudTrail, and AWS WAF) that are writing to S3 buckets, and generates CloudFormation
deployment commands for the EDOT Cloud Forwarder.

Usage:
    uv run edot-discover

Designed to run in AWS CloudShell with pre-configured credentials.
"""

import hashlib
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from urllib.parse import urlparse

import boto3
import questionary
from botocore.exceptions import ClientError, NoCredentialsError
from questionary import Choice, Separator
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

# Initialize rich console
console = Console()

# CloudFormation template URL
CLOUDFORMATION_TEMPLATE_URL = "https://edot-cloud-forwarder.s3.amazonaws.com/v0/latest/cloudformation/s3_logs-cloudformation.yaml"

# Map internal log_type to CloudFormation EdotCloudForwarderS3LogsType values
LOG_TYPE_MAP = {
    "vpc_flow_logs": "vpcflow",
    "elb_access_logs": "elbaccess",
    "cloudtrail": "cloudtrail",
    "waf": "waf",
}


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
        console.print(f"[yellow]Warning: Could not list regions: {e}[/yellow]")
        # Fallback to common regions
        return [default_region]
    except Exception as e:
        console.print(f"[yellow]Warning: Error listing regions: {e}[/yellow]")
        return [default_region]


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


def discover_flow_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover VPC Flow Logs writing to S3."""
    sources = []
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
        console.print(f"[yellow]Warning: Could not describe flow logs: {e}[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Warning: Error discovering flow logs: {e}[/yellow]")

    return sources


def discover_elb_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover ELB/ALB/NLB Access Logs writing to S3."""
    sources = []

    # Discover ALB/NLB via elbv2
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
                            console.print(
                                f"[yellow]Warning: {lb['LoadBalancerName']} in {region} "
                                "has access logging enabled but no S3 bucket "
                                "configured, skipping[/yellow]"
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
                    console.print(
                        f"[yellow]Warning: Could not get attributes for "
                        f"{lb['LoadBalancerName']}: {e}[/yellow]"
                    )
    except ClientError as e:
        console.print(f"[yellow]Warning: Could not describe ALB/NLB: {e}[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Warning: Error discovering ALB/NLB logs: {e}[/yellow]")

    # Discover Classic ELB via elb
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
                            console.print(
                                f"[yellow]Warning: Classic ELB {lb['LoadBalancerName']} "
                                f"in {region} has access logging enabled but no S3 "
                                "bucket configured, skipping[/yellow]"
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
                    console.print(
                        f"[yellow]Warning: Could not get attributes for Classic ELB "
                        f"{lb['LoadBalancerName']}: {e}[/yellow]"
                    )
    except ClientError as e:
        # Classic ELB API may not be available in all regions
        if "is not supported in this region" not in str(e):
            console.print(f"[yellow]Warning: Could not describe Classic ELB: {e}[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Warning: Error discovering Classic ELB logs: {e}[/yellow]")

    return sources


def discover_cloudtrail(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover CloudTrail trails writing to S3."""
    sources = []
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
        console.print(f"[yellow]Warning: Could not describe CloudTrail trails: {e}[/yellow]")
    except Exception as e:
        console.print(f"[yellow]Warning: Error discovering CloudTrail: {e}[/yellow]")

    return sources


def discover_waf_logs(session: boto3.Session, region: str) -> list[LogSource]:
    """Discover AWS WAF Web ACLs with logging to S3."""
    sources = []

    # WAFv2 has two scopes: REGIONAL and CLOUDFRONT
    # CLOUDFRONT scope is only available in us-east-1
    scopes = ["REGIONAL"]
    if region == "us-east-1":
        scopes.append("CLOUDFRONT")

    # Create wafv2 client once outside the loop
    wafv2 = session.client("wafv2", region_name=region)

    for scope in scopes:
        try:
            # List all Web ACLs for this scope
            paginator = wafv2.get_paginator("list_web_acls")
            for page in paginator.paginate(Scope=scope):
                for acl in page.get("WebACLs", []):
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
                            console.print(
                                f"[yellow]Warning: Could not get logging config "
                                f"for {acl_name}: {e}[/yellow]"
                            )
        except ClientError as e:
            console.print(f"[yellow]Warning: Could not list WAF Web ACLs ({scope}): {e}[/yellow]")
        except Exception as e:
            console.print(f"[yellow]Warning: Error discovering WAF logs ({scope}): {e}[/yellow]")

    return sources


def discover_all_sources(region: str) -> list[LogSource]:
    """Discover all log sources in the specified region."""
    session = boto3.Session(region_name=region)
    all_sources = []

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

    return all_sources


def display_results_table(sources: list[LogSource]) -> None:
    """Display discovered sources in a rich table."""
    table = Table(
        title=f"Discovered {len(sources)} Log Source(s)",
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("ID", style="magenta")
    table.add_column("Resource", max_width=35, overflow="ellipsis")
    table.add_column("S3 Destination", style="green", max_width=45, overflow="ellipsis")

    for source in sources:
        table.add_row(
            source.display_type,
            source.source_id,
            source.resource_id,
            source.destination,
        )

    console.print(table)


def build_selection_choices(sources: list[LogSource]) -> list:
    """Build grouped choices for questionary checkbox."""
    choices = []

    # Group by log type
    flow_logs = [s for s in sources if s.log_type == "vpc_flow_logs"]
    elb_logs = [s for s in sources if s.log_type == "elb_access_logs"]
    cloudtrail_logs = [s for s in sources if s.log_type == "cloudtrail"]
    waf_logs = [s for s in sources if s.log_type == "waf"]

    if flow_logs:
        choices.append(Separator("--- VPC Flow Logs ---"))
        for source in flow_logs:
            label = f"{source.source_id} ({source.resource_id}) -> {source.bucket_arn}"
            # Truncate long labels
            if len(label) > 80:
                label = label[:77] + "..."
            choices.append(Choice(title=label, value=source, checked=True))

    if elb_logs:
        choices.append(Separator("--- ELB Access Logs ---"))
        for source in elb_logs:
            label = f"{source.source_id} ({source.display_type}) -> {source.bucket_arn}"
            if len(label) > 80:
                label = label[:77] + "..."
            choices.append(Choice(title=label, value=source, checked=True))

    if cloudtrail_logs:
        choices.append(Separator("--- CloudTrail ---"))
        for source in cloudtrail_logs:
            label = f"{source.source_id} ({source.display_type}) -> {source.bucket_arn}"
            if len(label) > 80:
                label = label[:77] + "..."
            choices.append(Choice(title=label, value=source, checked=True))

    if waf_logs:
        choices.append(Separator("--- AWS WAF ---"))
        for source in waf_logs:
            label = f"{source.source_id} ({source.display_type}) -> {source.bucket_arn}"
            if len(label) > 80:
                label = label[:77] + "..."
            choices.append(Choice(title=label, value=source, checked=True))

    return choices


def generate_stack_name(bucket_arn: str, log_type: str) -> str:
    """
    Generate a deterministic, idempotent CloudFormation stack name.

    Stack names must:
    - Start with a letter
    - Contain only alphanumeric characters and hyphens
    - Be <= 128 characters
    """
    # Extract bucket name from ARN
    bucket_name = bucket_arn.replace("arn:aws:s3:::", "")

    # Create base name
    cf_log_type = LOG_TYPE_MAP.get(log_type, log_type)
    base_name = f"edot-cf-{cf_log_type}-{bucket_name}"

    # Sanitize: keep only alphanumeric and hyphens, ensure starts with letter
    sanitized = re.sub(r"[^a-zA-Z0-9-]", "-", base_name)
    sanitized = re.sub(r"-+", "-", sanitized)  # Collapse multiple hyphens
    sanitized = sanitized.strip("-")

    # Ensure starts with a letter
    if not sanitized[0].isalpha():
        sanitized = "s-" + sanitized

    # If too long, truncate and add hash for uniqueness
    max_len = 128
    if len(sanitized) > max_len:
        # Create a short hash of the full identifier
        full_id = f"{bucket_arn}-{log_type}"
        hash_suffix = hashlib.sha256(full_id.encode()).hexdigest()[:8]
        # Truncate base and append hash
        truncate_len = max_len - len(hash_suffix) - 1  # -1 for hyphen
        sanitized = sanitized[:truncate_len].rstrip("-") + "-" + hash_suffix

    return sanitized


def generate_cloudformation_command(
    stack_name: str,
    log_type: str,
    bucket_arn: str,
    otlp_endpoint: str,
    api_key: str,
    region: str,
) -> list[str]:
    """
    Generate a CloudFormation create-stack command as an argv list.

    Returns a list suitable for subprocess.run with shell=False.
    """
    # Map to CloudFormation expected log type value
    cf_log_type = LOG_TYPE_MAP.get(log_type, log_type)

    return [
        "aws",
        "cloudformation",
        "create-stack",
        "--stack-name",
        stack_name,
        "--template-url",
        CLOUDFORMATION_TEMPLATE_URL,
        "--capabilities",
        "CAPABILITY_NAMED_IAM",
        "--region",
        region,
        "--parameters",
        f"ParameterKey=OTLPEndpoint,ParameterValue={otlp_endpoint}",
        f"ParameterKey=ElasticAPIKey,ParameterValue={api_key}",
        f"ParameterKey=EdotCloudForwarderS3LogsType,ParameterValue={cf_log_type}",
        f"ParameterKey=SourceS3BucketARN,ParameterValue={bucket_arn}",
    ]


def redact_command_for_display(cmd: list[str]) -> str:
    """
    Convert command list to display string with sensitive values redacted.

    Redacts:
    - ElasticAPIKey parameter values
    - Common API key patterns
    """
    redacted_parts = []
    for part in cmd:
        # Redact ElasticAPIKey parameter
        if part.startswith("ParameterKey=ElasticAPIKey,ParameterValue="):
            redacted_parts.append("ParameterKey=ElasticAPIKey,ParameterValue=<REDACTED>")
        # Redact common API key patterns
        elif re.match(r"^(API_KEY|APIKEY|api_key|apikey)=", part):
            key_name = part.split("=")[0]
            redacted_parts.append(f"{key_name}=<REDACTED>")
        else:
            redacted_parts.append(part)

    return shlex.join(redacted_parts)


def generate_deployment_commands(
    selected_sources: list[LogSource],
    otlp_endpoint: str,
    api_key: str,
) -> list[tuple[str, str, str, list[str]]]:
    """
    Generate CloudFormation deployment commands for selected sources.

    Returns list of tuples: (display_name, bucket_arn, log_type, command_list)

    Note: One stack per unique bucket+log_type combination.
    """
    commands = []

    # Group sources by (bucket_arn, log_type, region)
    buckets_by_type: dict[tuple[str, str, str], list[LogSource]] = {}
    for source in selected_sources:
        key = (source.bucket_arn, source.log_type, source.region)
        if key not in buckets_by_type:
            buckets_by_type[key] = []
        buckets_by_type[key].append(source)

    # Generate one command per unique bucket+type+region
    for (bucket_arn, log_type, region), _sources in buckets_by_type.items():
        # Generate deterministic stack name
        stack_name = generate_stack_name(bucket_arn, log_type)

        # Set display name based on log type
        if log_type == "vpc_flow_logs":
            display_name = "VPC Flow Logs"
        elif log_type == "cloudtrail":
            display_name = "CloudTrail"
        elif log_type == "waf":
            display_name = "AWS WAF"
        else:
            display_name = "ELB Access Logs"

        cmd = generate_cloudformation_command(
            stack_name=stack_name,
            log_type=log_type,
            bucket_arn=bucket_arn,
            otlp_endpoint=otlp_endpoint,
            api_key=api_key,
            region=region,
        )

        commands.append((display_name, bucket_arn, log_type, cmd))

    return commands


def execute_deployment(command: list[str]) -> tuple[bool, str]:
    """Execute a CloudFormation deployment command."""
    try:
        result = subprocess.run(
            command,
            shell=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "Command timed out after 120 seconds"
    except Exception as e:
        return False, str(e)


def validate_otlp_endpoint(endpoint: str | None) -> bool:
    """
    Validate OTLP endpoint format.

    Requirements:
    - Must be a valid URL
    - Must use HTTPS scheme
    - Must have a non-empty host with at least one dot (domain) or be localhost
    """
    if not endpoint:
        return False

    try:
        parsed = urlparse(endpoint)
    except Exception:
        return False

    # Must be HTTPS
    if parsed.scheme != "https":
        return False

    # Must have a host
    if not parsed.netloc:
        return False

    # Host must be a valid domain (contains dot) or localhost
    host = parsed.netloc.split(":")[0]  # Remove port if present
    if "." not in host and host != "localhost":
        return False

    return True


def main():
    """Main entry point for the discovery tool."""
    console.print(
        Panel.fit(
            "[bold blue]EDOT Cloud Forwarder[/bold blue]\n"
            "[dim]AWS Log Source Discovery & Onboarding Tool[/dim]",
            border_style="blue",
        )
    )
    console.print()

    # Check AWS credentials
    try:
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        console.print(f"[green]AWS Account:[/green] {identity['Account']}")
        console.print(f"[green]Caller ARN:[/green] {identity['Arn']}")
    except NoCredentialsError:
        console.print(
            "[red]Error: No AWS credentials found.[/red]\n"
            "Please configure AWS credentials or run this tool in AWS CloudShell."
        )
        sys.exit(1)
    except ClientError as e:
        console.print(f"[red]Error verifying AWS credentials: {e}[/red]")
        sys.exit(1)

    console.print()

    # Get enabled regions and select
    default_region = get_default_region()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Fetching enabled regions...", total=None)
        regions = get_enabled_regions(default_region)

    # Build region choices with current region marked
    region_choices = []
    for r in regions:
        if r == default_region:
            region_choices.append(Choice(title=f"{r} (current)", value=r))
        else:
            region_choices.append(Choice(title=r, value=r))

    region = questionary.select(
        "Select AWS region to scan:",
        choices=region_choices,
    ).ask()

    if not region:
        console.print("[yellow]Operation cancelled.[/yellow]")
        sys.exit(0)

    console.print()

    # Discover log sources
    console.print(f"[bold]Scanning region {region} for log sources...[/bold]")
    sources = discover_all_sources(region)

    console.print()

    if not sources:
        console.print(
            Panel(
                "[yellow]No S3-backed log sources found in this region.[/yellow]\n\n"
                "EDOT Cloud Forwarder currently supports:\n"
                "  - VPC Flow Logs writing to S3\n"
                "  - ELB/ALB/NLB Access Logs writing to S3\n"
                "  - CloudTrail trails writing to S3\n"
                "  - AWS WAF logs writing to S3\n\n"
                "To set up logging:\n"
                "  - VPC Flow Logs: VPC Console -> Flow Logs -> Create\n"
                "  - ELB Access Logs: EC2 Console -> Load Balancers -> Attributes\n"
                "  - CloudTrail: CloudTrail Console -> Trails -> Create trail\n"
                "  - AWS WAF: WAF Console -> Web ACLs -> Logging",
                title="No Sources Found",
                border_style="yellow",
            )
        )
        sys.exit(0)

    # Display discovered sources
    display_results_table(sources)
    console.print()

    # Build selection choices
    choices = build_selection_choices(sources)

    # Multi-select sources (pre-selected, deselect to exclude)
    console.print(
        "[dim]All sources are pre-selected. Use arrow keys to navigate, "
        "Space to toggle, Enter to confirm.[/dim]"
    )
    selected = questionary.checkbox(
        "Select log sources to onboard:",
        choices=choices,
    ).ask()

    if not selected:
        console.print("[yellow]No sources selected. Exiting.[/yellow]")
        sys.exit(0)

    console.print()
    console.print(f"[green]Selected {len(selected)} source(s) for onboarding.[/green]")
    console.print()

    # Collect Elastic Cloud configuration
    console.print(
        Panel(
            "Enter your Elastic Cloud OTLP endpoint and API key.\n"
            "Find these in Kibana: Management -> Fleet -> Agent Policies -> OTLP Endpoint",
            title="Elastic Cloud Configuration",
            border_style="cyan",
        )
    )
    console.print()

    otlp_endpoint = questionary.text(
        "OTLP Endpoint URL (https://...):",
        validate=lambda x: validate_otlp_endpoint(x) or "Enter a valid HTTPS endpoint URL",
    ).ask()

    if not otlp_endpoint:
        console.print("[yellow]Operation cancelled.[/yellow]")
        sys.exit(0)

    api_key = questionary.password(
        "Elastic API Key:",
        validate=lambda x: len(x) >= 32 or "API key must be at least 32 characters",
    ).ask()

    if not api_key:
        console.print("[yellow]Operation cancelled.[/yellow]")
        sys.exit(0)

    console.print()

    # Generate deployment commands
    commands = generate_deployment_commands(selected, otlp_endpoint, api_key)

    # Display dry-run preview
    console.print(
        Panel(
            "[bold]Review the CloudFormation commands below before execution.[/bold]\n"
            "One stack will be created per unique S3 bucket and log type combination.",
            title="Dry Run Preview",
            border_style="yellow",
        )
    )
    console.print()

    for i, (display_name, bucket_arn, _log_type, cmd) in enumerate(commands, 1):
        console.print(f"[bold cyan]Stack {i}: {display_name}[/bold cyan]")
        console.print(f"[green]Bucket:[/green] {bucket_arn}")
        # Display redacted command
        redacted_cmd = redact_command_for_display(cmd)
        console.print(f"[dim]{redacted_cmd}[/dim]")
        console.print()

    # Confirm execution
    execute = questionary.confirm(
        f"Execute {len(commands)} CloudFormation deployment(s)?",
        default=False,
    ).ask()

    if not execute:
        console.print()
        console.print(
            "[yellow]Deployment cancelled. Commands have been printed above - "
            "copy and run manually when ready.[/yellow]"
        )
        sys.exit(0)

    console.print()

    # Execute deployments
    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for display_name, bucket_arn, _log_type, cmd in commands:
            task = progress.add_task(f"Deploying {display_name}...", total=None)
            success, output = execute_deployment(cmd)
            progress.remove_task(task)

            if success:
                console.print(
                    f"[green]Stack creation initiated for {display_name} ({bucket_arn})[/green]"
                )
            else:
                console.print(f"[red]Failed to create stack for {display_name}: {output}[/red]")

            results.append((display_name, bucket_arn, success, output))

    console.print()

    # Summary
    successful = sum(1 for _, _, success, _ in results if success)
    failed = len(results) - successful

    if failed == 0:
        console.print(
            Panel(
                f"[green]All {successful} stack(s) initiated successfully![/green]\n\n"
                "Monitor stack creation progress:\n"
                f"  aws cloudformation list-stacks --region {region} "
                "--stack-status-filter CREATE_IN_PROGRESS CREATE_COMPLETE\n\n"
                "View stack events:\n"
                "  aws cloudformation describe-stack-events --stack-name <stack-name>",
                title="Deployment Complete",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                f"[yellow]{successful} stack(s) initiated, {failed} failed.[/yellow]\n\n"
                "Review the errors above and retry failed deployments manually.",
                title="Deployment Partially Complete",
                border_style="yellow",
            )
        )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled by user.[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {e}[/red]")
        sys.exit(1)
