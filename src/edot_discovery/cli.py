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

from .discovery import LogSource, discover_all_sources
from .discovery.utils import (
    bold,
    cancel,
    dim,
    error,
    generate_cloudformation_command,
    generate_stack_name,
    get_bucket_region,
    get_default_region,
    get_enabled_regions,
    redact_command_for_display,
    success,
    validate_otlp_endpoint,
    warning,
)

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
    table.add_column("Status", max_width=35, overflow="ellipsis")

    for source in sources:
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

        table.add_row(
            source.display_type,
            source.source_id,
            source.destination,
            status,
        )

    console.print(table)


def _build_choice_label(source: LogSource) -> str:
    """Build a display label for a source in the selection UI."""
    if source.existing_forwarder:
        # Show that it's already configured with the stack name
        stack_name = source.existing_forwarder.stack_name
        label = f"{source.source_id} -> {source.bucket_arn} [CONFIGURED: {stack_name}]"
    else:
        label = f"{source.source_id} ({source.display_type}) -> {source.bucket_arn}"

    # Truncate long labels
    if len(label) > 90:
        label = label[:87] + "..."
    return label


def build_selection_choices(sources: list[LogSource]) -> list[Choice | Separator]:
    """Build grouped choices for questionary checkbox."""
    choices: list[Choice | Separator] = []

    # Configuration for each log type group
    log_type_groups = [
        ("vpc_flow_logs", "--- VPC Flow Logs ---"),
        ("elb_access_logs", "--- ELB Access Logs ---"),
        ("cloudtrail", "--- CloudTrail ---"),
        ("waf", "--- AWS WAF ---"),
    ]

    for log_type, separator_label in log_type_groups:
        group_sources = [s for s in sources if s.log_type == log_type]
        if not group_sources:
            continue

        choices.append(Separator(separator_label))
        for source in group_sources:
            label = _build_choice_label(source)
            # Sources with existing forwarders are unchecked by default
            is_checked = source.existing_forwarder is None
            choices.append(Choice(title=label, value=source, checked=is_checked))

    return choices


def generate_deployment_commands(
    selected_sources: list[LogSource],
    otlp_endpoint: str,
    api_key: str,
    session: boto3.Session | None = None,
) -> list[tuple[str, str, str, list[str]]]:
    """
    Generate CloudFormation deployment commands for selected sources.

    Args:
        selected_sources: List of LogSource objects to generate commands for
        otlp_endpoint: OTLP endpoint URL for Elastic Cloud
        api_key: Elastic API key
        session: Optional boto3 Session. If not provided, creates a new session.

    Returns:
        List of tuples: (display_name, bucket_arn, log_type, command_list)

    Note: One stack per unique bucket+log_type combination.
    Uses the bucket's actual region (not the resource region) for deployment.
    """
    if session is None:
        session = boto3.Session()

    commands: list[tuple[str, str, str, list[str]]] = []

    # Group sources by (bucket_arn, log_type) - we'll determine bucket region separately
    buckets_by_type: dict[tuple[str, str], list[LogSource]] = {}
    for source in selected_sources:
        key = (source.bucket_arn, source.log_type)
        if key not in buckets_by_type:
            buckets_by_type[key] = []
        buckets_by_type[key].append(source)

    # Generate one command per unique bucket+type, using bucket's actual region
    for (bucket_arn, log_type), sources in buckets_by_type.items():
        # Get the bucket's actual region
        bucket_region = get_bucket_region(bucket_arn, session)

        if bucket_region is None:
            # Fallback to first source's region if we can't determine bucket region
            bucket_region = sources[0].region
            warning(
                f"Using resource region {bucket_region} for bucket {bucket_arn} "
                "(could not determine bucket region). This may cause deployment issues if the "
                "bucket is in a different region."
            )
        else:
            # Check if any sources have a different region than the bucket
            # This is valid - services can write cross-region, but notifications require same-region
            resource_regions = {s.region for s in sources}
            if bucket_region not in resource_regions:
                warning(
                    f"Note: Bucket {bucket_arn} is in {bucket_region}, but resources "
                    f"are in {', '.join(resource_regions)}. This is valid - services can write "
                    f"cross-region, but deploying stack in bucket region {bucket_region} "
                    f"(required for S3 notifications)."
                )

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
            region=bucket_region,
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

    # Display discovered sources
    display_results_table(sources)
    console.print()

    # Build selection choices
    choices = build_selection_choices(sources)

    # Count already-configured sources for messaging
    already_configured = sum(1 for s in sources if s.existing_forwarder)
    if already_configured > 0:
        dim(
            f"Sources not yet configured are pre-selected. "
            f"{already_configured} source(s) already have forwarders (marked [CONFIGURED])."
        )
    else:
        dim(
            "All sources are pre-selected. Use arrow keys to navigate, "
            "Space to toggle, Enter to confirm."
        )

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
        cancel("Operation cancelled.")
        sys.exit(0)

    api_key = questionary.password(
        "Elastic API Key:",
        validate=lambda x: len(x) >= 32 or "API key must be at least 32 characters",
    ).ask()

    if not api_key:
        cancel("Operation cancelled.")
        sys.exit(0)

    console.print()

    # Generate deployment commands (only for new sources, not already-configured)
    commands = generate_deployment_commands(new_sources, otlp_endpoint, api_key)

    # Display dry-run preview
    console.print(
        Panel(
            "Review the CloudFormation commands below before execution.\n"
            "One stack will be created per unique S3 bucket and log type combination.",
            title="Dry Run Preview",
            border_style="yellow",
        )
    )
    console.print()

    for i, (display_name, bucket_arn, _log_type, cmd) in enumerate(commands, 1):
        console.print(f"[bold cyan]Stack {i}: {display_name}[/bold cyan]")
        success(f"Bucket: {bucket_arn}")
        # Display redacted command
        redacted_cmd = redact_command_for_display(cmd)
        dim(redacted_cmd)
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
        for display_name, bucket_arn, _log_type, cmd in commands:
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


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        cancel("\nOperation cancelled by user.")
        sys.exit(130)
    except Exception as e:
        error(f"\nUnexpected error: {e}")
        sys.exit(1)
