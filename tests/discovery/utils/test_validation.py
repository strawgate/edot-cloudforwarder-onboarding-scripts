"""Tests for edot_discovery.discovery.utils.validation."""

import pytest
from inline_snapshot import snapshot

from edot_discovery.discovery.utils.validation import validate_otlp_endpoint


class TestValidateOtlpEndpoint:
    """Tests for validate_otlp_endpoint function."""

    @pytest.mark.parametrize(
        "endpoint",
        [
            "https://example.apm.aws.cloud.es.io:443",
            "https://example.com",
            "https://my-deployment.apm.us-west-2.aws.cloud.es.io",
            "https://localhost:8080",
            "https://127.0.0.1:443",
        ],
    )
    def test_accepts_valid_https_endpoints(self, endpoint: str):
        """Test that valid HTTPS endpoints are accepted."""
        assert validate_otlp_endpoint(endpoint) is True

    @pytest.mark.parametrize(
        ("endpoint", "reason"),
        [
            ("http://example.com", "http not https"),
            ("ftp://example.com", "invalid scheme"),
            ("", "empty string"),
            ("https://nodomain", "no TLD"),
            ("example.com", "missing scheme"),
        ],
    )
    def test_rejects_invalid_endpoints(self, endpoint: str, reason: str):
        """Test that invalid endpoints are rejected."""
        assert validate_otlp_endpoint(endpoint) is False, f"Should reject: {reason}"

    def test_rejects_none(self):
        """Test that None is rejected without raising an exception."""
        assert validate_otlp_endpoint(None) == snapshot(False)
