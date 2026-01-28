# Development Guide

This guide covers setting up a development environment and working on the EDOT Discovery Tool.

## Prerequisites

- Git
- AWS credentials (for integration testing)

## Quick Setup with uv

This project uses [uv](https://github.com/astral-sh/uv) for dependency management. Install it first:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

Then clone and run:

```bash
# Clone the repository
git clone https://github.com/strawgate/edot-cloudforwarder-onboarding-scripts.git
cd edot-cloudforwarder-onboarding-scripts

# Run the tool (uv automatically handles venv and dependencies)
uv run edot-discover
```

For development with dev dependencies:

```bash
# Install dev dependencies explicitly (for IDE support)
uv sync --dev

# Run the tool
uv run edot-discover
```

## Project Structure

```text
edot-cloudforwarder-onboarding-scripts/
├── src/
│   └── edot_discovery/
│       ├── __init__.py      # Package version
│       └── cli.py           # Main CLI logic
├── tests/
│   ├── __init__.py
│   ├── conftest.py          # Pytest fixtures
│   └── test_cli.py          # CLI tests
├── install.sh               # One-line installer
├── pyproject.toml           # Project configuration (dependencies, metadata)
├── README.md
├── CONTRIBUTING.md
├── CODE_STYLE.md
└── DEVELOPING.md            # This file
```

## Running Tests

```bash
# Run all tests
uv run pytest

# Run with coverage
uv run pytest --cov

# Run specific test file
uv run pytest tests/test_cli.py

# Run specific test
uv run pytest tests/test_cli.py::TestExtractBucketArn::test_arn_format_with_prefix

# Run with verbose output
uv run pytest -v
```

## Linting and Formatting

```bash
# Check linting
uv run ruff check .

# Fix auto-fixable issues
uv run ruff check --fix .

# Check formatting
uv run ruff format --check .

# Apply formatting
uv run ruff format .

# Type checking
uv run mypy src
```

## Pre-commit Checks

Before committing, run the full check suite:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
```

Or create a script:

```bash
#!/bin/bash
set -e
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
echo "All checks passed!"
```

## Testing with AWS

For integration testing with real AWS resources:

1. Configure AWS credentials:

   ```bash
   aws configure
   # Or use environment variables:
   export AWS_ACCESS_KEY_ID=...
   export AWS_SECRET_ACCESS_KEY=...
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. Run the tool manually:

   ```bash
   uv run edot-discover
   ```

3. The tool will discover real resources in your account

## Adding New Features

1. **Create a branch**:

   ```bash
   git checkout -b feature/my-feature
   ```

2. **Write tests first** (TDD recommended):

   ```python
   # tests/test_cli.py
   def test_my_new_feature():
       result = my_new_function("input")
       assert result == "expected"
   ```

3. **Implement the feature** in `src/edot_discovery/cli.py`

4. **Run tests and linting**:

   ```bash
   uv run pytest
   uv run ruff check .
   ```

5. **Update documentation** if needed

6. **Commit and push**:

   ```bash
   git add .
   git commit -m "Add my feature"
   git push origin feature/my-feature
   ```

## Debugging Tips

### Enable boto3 debug logging

```python
import logging
logging.getLogger('boto3').setLevel(logging.DEBUG)
logging.getLogger('botocore').setLevel(logging.DEBUG)
```

### Test with mock AWS responses

Use the fixtures in `conftest.py` or create mocks:

```python
from unittest.mock import MagicMock, patch

@patch('boto3.client')
def test_with_mock(mock_client):
    mock_client.return_value.describe_flow_logs.return_value = {
        "FlowLogs": [...]
    }
    # Test your function
```

### Interactive debugging

```python
# Add breakpoint in code
breakpoint()

# Run pytest with -s to see output
uv run pytest -s tests/test_cli.py::test_name
```

## Release Process

1. Update version in `src/edot_discovery/__init__.py`
2. Update version in `pyproject.toml`
3. Create a git tag: `git tag v0.1.0`
4. Push with tags: `git push --tags`

## Useful Commands Reference

| Command | Description |
|---------|-------------|
| `uv run edot-discover` | Run the discovery tool |
| `uv run pytest` | Run tests |
| `uv run ruff check .` | Lint code |
| `uv run ruff format .` | Format code |
| `uv run mypy src` | Type check |
| `uv sync --dev` | Explicitly sync dev dependencies (for IDE support) |
