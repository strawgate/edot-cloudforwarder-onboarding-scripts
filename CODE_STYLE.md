# Code Style Guide

This document describes the code style choices for this project, including any deviations from standard Python conventions.

## Tooling

We use the following tools for code quality:

- **Ruff**: Linting and formatting (replaces black, isort, flake8)
- **mypy**: Static type checking
- **pytest**: Testing

Run all checks with:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

## Style Choices

### Line Length

We use 100 characters per line instead of the PEP 8 default of 79. This provides more readable code on modern displays while still being reasonable for side-by-side diffs.

### Import Organization

Imports are organized by ruff/isort into three groups:

1. Standard library
2. Third-party packages
3. Local imports

Within each group, imports are sorted alphabetically.

### Type Annotations

- All public functions must have type annotations
- Use `list[str]` instead of `List[str]` (Python 3.10+)
- Use `| None` instead of `Optional[...]`
- Use `dict[str, Any]` for complex dynamic structures

### Docstrings

We use Google-style docstrings:

```python
def function(arg1: str, arg2: int) -> bool:
    """Short description.

    Longer description if needed.

    Args:
        arg1: Description of arg1.
        arg2: Description of arg2.

    Returns:
        Description of return value.

    Raises:
        ValueError: When something is wrong.
    """
```

### Error Handling

- Use specific exception types, not bare `except:`
- Log warnings for recoverable errors, don't silently ignore
- Provide helpful error messages to users

### Security Patterns

- **Never** use `shell=True` with `subprocess.run()`
- **Always** redact sensitive values (API keys) in logs and output
- **Validate** user input before use
- **Use** `shlex.join()` for displaying commands, not string concatenation

### AWS Client Patterns

```python
# Preferred: Use paginator for list operations
paginator = client.get_paginator("describe_foo")
for page in paginator.paginate():
    for item in page.get("Items", []):
        process(item)

# Create clients with explicit region
client = session.client("ec2", region_name=region)
```

### Rich Console Output

- Use `[green]` for success, `[yellow]` for warnings, `[red]` for errors
- Use `[dim]` for less important information
- Use `Panel` for important grouped information
- Use `Table` for structured data

### dataclasses

Use `@dataclass` for simple data containers:

```python
@dataclass
class LogSource:
    """Represents a discovered log source."""

    log_type: str
    source_id: str
    bucket_arn: str
```

## Ruff Configuration

See `pyproject.toml` for the complete ruff configuration. Key settings:

- Line length: 100
- Target: Python 3.10
- Selected rules: E, W, F, I, B, C4, UP, S, T20
- Ignored: S603, S607 (subprocess rules - we use shell=False intentionally)

## Naming Conventions

- **Functions**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private functions**: `_leading_underscore`
- **Module-level "private"**: `_leading_underscore`

## Testing Style

- One test class per function/feature
- Descriptive test names: `test_extract_bucket_arn_with_prefix`
- Use fixtures for shared test data
- Test both success and error cases
