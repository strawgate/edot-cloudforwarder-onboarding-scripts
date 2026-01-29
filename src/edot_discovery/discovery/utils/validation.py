"""Input validation utilities."""

from urllib.parse import urlparse


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
