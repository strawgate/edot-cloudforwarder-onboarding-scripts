"""Console output helpers for consistent styling."""

from rich.console import Console

# Shared console for all output
console = Console()


def success(message: str) -> None:
    """Print a success message in green."""
    console.print(f"[green]{message}[/green]")


def error(message: str) -> None:
    """Print an error message in red."""
    console.print(f"[red]{message}[/red]")


def warning(message: str) -> None:
    """Print a warning message in yellow."""
    console.print(f"[yellow]{message}[/yellow]")


def dim(message: str) -> None:
    """Print a dimmed/secondary message."""
    console.print(f"[dim]{message}[/dim]")


def bold(message: str) -> None:
    """Print a bold message."""
    console.print(f"[bold]{message}[/bold]")


def cancel(message: str) -> None:
    """Print a cancellation message in yellow."""
    console.print(f"[yellow]{message}[/yellow]")
