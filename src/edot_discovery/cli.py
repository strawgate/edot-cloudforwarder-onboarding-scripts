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

import subprocess
import sys
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

from edot_discovery.discovery.coordinator import discover_all_sources
from edot_discovery.discovery.stacks.commands import generate_deployment_commands
from edot_discovery.discovery.types import LogSource
from edot_discovery.discovery.utils.bucket import get_bucket_region
from edot_discovery.discovery.utils.cloudformation import redact_command_for_display
from edot_discovery.discovery.utils.console import (
    bold,
    cancel,
    dim,
    error,
    success,
    warning,
)
from edot_discovery.discovery.utils.regions import get_default_region, get_enabled_regions
from edot_discovery.discovery.utils.validation import validate_otlp_endpoint

# Initialize rich console
console = Console()


def display_results_table(sources: list[LogSource]) -> None:
    """Display discovered sources in a rich table."""
    # Count sources with existing forwarders
    configured_count = sum(1 for s in sources if s.existing_forwarder)

    title = f"Discovered {len(sources)} Log Source(s)"
    if configured_count > 0:
        title += f" ({configured_count} already forwarding)"

    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=True,
    )
    table.add_column("Type", style="cyan", no_wrap=True)
    table.add_column("ID", style="magenta")
    table.add_column("S3 Destination", style="green", max_width=40, overflow="ellipsis")
    table.add_column("Forwarder Status", max_width=35, overflow="ellipsis")

    for source in sources:
        # Check if there's a warning (unknown bucket region)
        has_warning = source.bucket_region is None

        if source.existing_forwarder:
            # Extract host from OTLP endpoint for brevity
            endpoint = source.existing_forwarder.otlp_endpoint
            try:
                host = urlparse(endpoint).netloc or endpoint
            except Exception:
                host = endpoint
            status = f"[green]Forwarding → {host}[/green]"
        else:
            status = "[dim]Not configured[/dim]"

        # Add warning icon to type column if there's a warning
        type_display = source.display_type
        if has_warning:
            type_display = f"⚠ {type_display}"

        # Format S3 destination with warning text on second line if needed
        destination_display = source.destination
        if has_warning:
            destination_display = (
                f"{source.destination}\n[dim](may not exist or access denied)[/dim]"
            )

        # Style the row based on warning status
        row_style = "yellow" if has_warning else None

        table.add_row(
            type_display,
            source.source_id,
            destination_display,
            status,
            style=row_style,
        )

    console.print(table)


def _extract_bucket_name(bucket_arn: str) -> str:
    """Extract bucket name from ARN."""
    return bucket_arn.replace("arn:aws:s3:::", "")


def _extract_host_from_endpoint(endpoint: str) -> str:
    """Extract host from OTLP endpoint for brevity."""
    try:
        return urlparse(endpoint).netloc or endpoint
    except Exception:
        return endpoint


def _build_choice_label(source: LogSource) -> str:
    """Build a display label for a source in the selection UI."""
    bucket_name = _extract_bucket_name(source.bucket_arn)

    # Start with warning symbol if bucket region is unknown
    warning_prefix = "⚠ " if source.bucket_region is None else ""

    if source.existing_forwarder:
        # Show that it's already configured
        host = _extract_host_from_endpoint(source.existing_forwarder.otlp_endpoint)
        label = (
            f"{warning_prefix}s3://{bucket_name}  │  {source.source_id}  │  ✓ Configured → {host}"
        )
    else:
        # Just bucket and source ID (type is already in section header)
        label = f"{warning_prefix}s3://{bucket_name}  │  {source.source_id}"

    # Truncate long labels if needed
    if len(label) > 120:
        # Truncate bucket name if needed
        if len(bucket_name) > 40:
            truncated_bucket = bucket_name[:37] + "..."
            if source.existing_forwarder:
                host = _extract_host_from_endpoint(source.existing_forwarder.otlp_endpoint)
                label = (
                    f"{warning_prefix}s3://{truncated_bucket}  │  {source.source_id}  │  "
                    f"✓ Configured → {host}"
                )
            else:
                label = f"{warning_prefix}s3://{truncated_bucket}  │  {source.source_id}"
        # If still too long, truncate the whole thing
        if len(label) > 120:
            label = label[:117] + "..."

    return label


def build_selection_choices(sources: list[LogSource]) -> list[Choice | Separator]:
    """Build grouped choices for questionary checkbox."""
    choices: list[Choice | Separator] = []

    # Configuration for each log type group
    log_type_groups = [
        ("vpc_flow_logs", "VPC Flow Logs"),
        ("elb_access_logs", "ELB Access Logs"),
        ("cloudtrail", "CloudTrail"),
        ("waf", "AWS WAF"),
    ]

    for log_type, separator_label in log_type_groups:
        group_sources = [s for s in sources if s.log_type == log_type]
        if not group_sources:
            continue

        # Add newline before section header
        separator_label = f"\n{separator_label}"

        choices.append(Separator(separator_label))
        for source in group_sources:
            label = _build_choice_label(source)
            # Uncheck sources that already have forwarders or have unknown bucket regions
            is_checked = source.existing_forwarder is None and source.bucket_region is not None
            choices.append(Choice(title=label, value=source, checked=is_checked))

    return choices


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


def main() -> None:
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
        success(f"AWS Account: {identity['Account']}")
        success(f"Caller ARN: {identity['Arn']}")
    except NoCredentialsError:
        error(
            "Error: No AWS credentials found.\n"
            "Please configure AWS credentials or run this tool in AWS CloudShell."
        )
        sys.exit(1)
    except ClientError as e:
        error(f"Error verifying AWS credentials: {e}")
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
    region_choices: list[Choice] = []
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
        cancel("Operation cancelled.")
        sys.exit(0)

    console.print()

    # Discover log sources
    bold(f"Scanning region {region} for log sources...")
    sources = discover_all_sources(region)

    console.print()

    if not sources:
        console.print(
            Panel(
                "No S3-backed log sources found in this region.\n\n"
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

    # Look up bucket regions for all unique buckets
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Looking up bucket regions...", total=None)
        unique_buckets = {s.bucket_arn for s in sources}
        bucket_regions: dict[str, str | None] = {}
        for bucket_arn in unique_buckets:
            bucket_regions[bucket_arn] = get_bucket_region(bucket_arn)

        # Annotate sources with bucket region
        for source in sources:
            source.bucket_region = bucket_regions.get(source.bucket_arn)

    # Count buckets with unknown regions (for selection message)
    unknown_count = sum(1 for r in bucket_regions.values() if r is None)
    has_unknown_buckets = unknown_count > 0

    # Display discovered sources
    display_results_table(sources)

    # Build selection choices
    choices = build_selection_choices(sources)

    # Count already-configured sources for messaging
    already_configured = sum(1 for s in sources if s.existing_forwarder)

    if already_configured > 0 and has_unknown_buckets:
        dim(
            f"Pre-selected for deployment: Sources without warnings or errors. "
            f"{already_configured} source(s) already have forwarders (marked [CONFIGURED]) "
            f"and are excluded."
        )
    elif already_configured > 0:
        dim(
            f"Pre-selected for deployment: Sources without warnings or errors. "
            f"{already_configured} source(s) already have forwarders (marked [CONFIGURED]) "
            f"and are excluded."
        )
    elif has_unknown_buckets:
        dim("Pre-selected for deployment: Sources without warnings or errors.")
    else:
        dim("Pre-selected for deployment: All sources.")

    # Add explanation about what the icons mean
    dim("● = Will be deployed  |  ○ = Will not be deployed")
    console.print()

    selected: list[LogSource] = questionary.checkbox(
        "Select log sources to onboard:",
        choices=choices,
    ).ask()

    if not selected:
        warning("No sources selected. Exiting.")
        sys.exit(0)

    console.print()

    # Separate new sources from already-configured ones
    new_sources = [s for s in selected if s.existing_forwarder is None]
    skipped_sources = [s for s in selected if s.existing_forwarder is not None]

    if skipped_sources:
        warning(f"Skipping {len(skipped_sources)} already-configured source(s):")
        for s in skipped_sources:
            stack_name = s.existing_forwarder.stack_name  # type: ignore[union-attr]
            dim(f"  - {s.source_id} ({stack_name})")
        console.print()

    if not new_sources:
        warning("All selected sources are already configured. Nothing to deploy.")
        sys.exit(0)

    success(f"Selected {len(new_sources)} new source(s) for onboarding.")
    console.print()

    # Collect Elastic Cloud configuration
    console.print(
        Panel(
            "Enter your Elastic Cloud OTLP endpoint and API key.\n"
            "Find these in Kibana: Add Data -> Application -> OpenTelemetry -> "
            "OTEL_EXPORTER_OTLP_ENDPOINT and OTEL_EXPORTER_OTLP_HEADERS (everything after ApiKey)",
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
        cancel("Operation cancelled.")
        sys.exit(0)

    api_key = questionary.password(
        "Elastic API Key:",
        validate=lambda x: len(x) >= 32 or "API key must be at least 32 characters",
    ).ask()

    if not api_key:
        cancel("Operation cancelled.")
        sys.exit(0)

    # Strip "Authorization=ApiKey " prefix if present (user might paste full header value)
    if api_key.startswith("Authorization=ApiKey "):
        api_key = api_key[len("Authorization=ApiKey ") :]
        dim("Stripped 'Authorization=ApiKey ' prefix from API key")

    console.print()

    # Generate deployment commands (only for new sources, not already-configured)
    commands = generate_deployment_commands(new_sources, otlp_endpoint, api_key)

    # Display dry-run preview
    console.print(
        Panel(
            "Review the CloudFormation commands below before execution.\n"
            "One stack will be created per unique S3 bucket and log type combination.\n\n"
            "Commands are formatted for copy/paste if you prefer to run manually.\n"
            "[dim]Note: API key is shown as <REDACTED> - substitute your actual key.[/dim]",
            title="Dry Run Preview",
            border_style="yellow",
        )
    )
    console.print()

    for i, (display_name, bucket_arn, bucket_region, _log_type, cmd) in enumerate(commands, 1):
        # Format as bash comments so output can be copied and run as a script
        console.print(f"[bold cyan]# Stack {i} ({bucket_region}): {display_name}[/bold cyan]")
        console.print(f"[green]# Bucket: {bucket_arn}[/green]")
        # Display redacted command
        redacted_cmd = redact_command_for_display(cmd)
        console.print(redacted_cmd)
        console.print()

    # Confirm execution
    execute = questionary.confirm(
        f"Execute {len(commands)} CloudFormation deployment(s)?",
        default=False,
    ).ask()

    if not execute:
        console.print()
        warning(
            "Deployment cancelled. Commands have been printed above - "
            "copy and run manually when ready."
        )
        sys.exit(0)

    console.print()

    # Execute deployments
    results: list[tuple[str, str, bool, str]] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        for display_name, bucket_arn, _bucket_region, _log_type, cmd in commands:
            task = progress.add_task(f"Deploying {display_name}...", total=None)
            deployment_success, output = execute_deployment(cmd)
            progress.remove_task(task)

            if deployment_success:
                success(f"Stack creation initiated for {display_name} ({bucket_arn})")
            else:
                error(f"Failed to create stack for {display_name}: {output}")

            results.append((display_name, bucket_arn, deployment_success, output))

    console.print()

    # Summary
    successful = sum(1 for _, _, deployment_success, _ in results if deployment_success)
    failed = len(results) - successful

    if failed == 0:
        console.print(
            Panel(
                f"All {successful} stack(s) initiated successfully!\n\n"
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
                f"{successful} stack(s) initiated, {failed} failed.\n\n"
                "Review the errors above and retry failed deployments manually.",
                title="Deployment Partially Complete",
                border_style="yellow",
            )
        )

    # Explicit exit to ensure clean termination (especially when run via install script)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cancel("\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        error(f"\nUnexpected error: {e}")
        sys.exit(1)
