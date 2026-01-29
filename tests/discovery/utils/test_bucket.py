"""Tests for edot_discovery.discovery.utils.bucket."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from inline_snapshot import snapshot

from edot_discovery.discovery.utils.bucket import extract_bucket_arn, get_bucket_region

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_s3_client() -> MagicMock:
    """Create a mock S3 client."""
    return MagicMock()


@pytest.fixture
def mock_session(mock_s3_client: MagicMock) -> MagicMock:
    """Create a mock boto3 Session that returns the mock S3 client."""
    session = MagicMock()
    session.client.return_value = mock_s3_client
    return session


# =============================================================================
# Tests for extract_bucket_arn
# =============================================================================


class TestExtractBucketArn:
    """Tests for extract_bucket_arn function."""

    @pytest.mark.parametrize(
        ("destination", "expected"),
        [
            ("arn:aws:s3:::my-bucket/prefix/subprefix/", "arn:aws:s3:::my-bucket"),
            ("arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket"),
            ("s3://my-bucket/prefix/", "arn:aws:s3:::my-bucket"),
            ("s3://my-bucket", "arn:aws:s3:::my-bucket"),
            ("unknown-format", "unknown-format"),
            ("", ""),
        ],
    )
    def test_extract_bucket_arn(self, destination: str, expected: str):
        """Test extracting bucket ARN from various destination formats."""
        assert extract_bucket_arn(destination) == expected


# =============================================================================
# Tests for get_bucket_region
# =============================================================================


class TestGetBucketRegion:
    """Tests for get_bucket_region function."""

    def test_returns_region_from_location_constraint(
        self, mock_session: MagicMock, mock_s3_client: MagicMock
    ):
        """Test getting bucket region for a standard region."""
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "us-west-2"}

        result = get_bucket_region("arn:aws:s3:::my-bucket", mock_session)

        assert result == snapshot("us-west-2")
        mock_s3_client.get_bucket_location.assert_called_once_with(Bucket="my-bucket")

    def test_us_east_1_returns_none_from_api(
        self, mock_session: MagicMock, mock_s3_client: MagicMock
    ):
        """Test that us-east-1 buckets return None from API and are handled correctly."""
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": None}

        result = get_bucket_region("arn:aws:s3:::my-bucket", mock_session)

        assert result == snapshot("us-east-1")

    def test_empty_location_constraint_returns_us_east_1(
        self, mock_session: MagicMock, mock_s3_client: MagicMock
    ):
        """Test that empty location constraint is handled as us-east-1."""
        mock_s3_client.get_bucket_location.return_value = {}

        result = get_bucket_region("arn:aws:s3:::my-bucket", mock_session)

        assert result == snapshot("us-east-1")

    def test_client_error_returns_none(self, mock_session: MagicMock, mock_s3_client: MagicMock):
        """Test that ClientError returns None."""
        mock_s3_client.get_bucket_location.side_effect = ClientError(
            {"Error": {"Code": "NoSuchBucket", "Message": "Bucket not found"}},
            "GetBucketLocation",
        )

        result = get_bucket_region("arn:aws:s3:::my-bucket", mock_session)

        assert result is None

    def test_generic_exception_returns_none(
        self, mock_session: MagicMock, mock_s3_client: MagicMock
    ):
        """Test that generic exceptions return None."""
        mock_s3_client.get_bucket_location.side_effect = Exception("Unexpected error")

        result = get_bucket_region("arn:aws:s3:::my-bucket", mock_session)

        assert result is None

    def test_creates_session_if_none_provided(self):
        """Test that function creates a session if none is provided."""
        with patch("edot_discovery.discovery.utils.bucket.boto3.Session") as mock_session_class:
            mock_session = MagicMock()
            mock_s3_client = MagicMock()
            mock_session_class.return_value = mock_session
            mock_session.client.return_value = mock_s3_client
            mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "eu-west-1"}

            result = get_bucket_region("arn:aws:s3:::my-bucket")

            assert result == snapshot("eu-west-1")
            mock_session_class.assert_called_once()

    @pytest.mark.parametrize(
        ("bucket_arn", "expected_bucket_name"),
        [
            ("arn:aws:s3:::my-bucket", "my-bucket"),
            ("arn:aws:s3:::my-complex-bucket-name", "my-complex-bucket-name"),
            ("arn:aws:s3:::123-numeric-start", "123-numeric-start"),
        ],
    )
    def test_extracts_bucket_name_from_arn(
        self,
        mock_session: MagicMock,
        mock_s3_client: MagicMock,
        bucket_arn: str,
        expected_bucket_name: str,
    ):
        """Test that bucket name is correctly extracted from various ARN formats."""
        mock_s3_client.get_bucket_location.return_value = {"LocationConstraint": "ap-southeast-1"}

        result = get_bucket_region(bucket_arn, mock_session)

        assert result == snapshot("ap-southeast-1")
        mock_s3_client.get_bucket_location.assert_called_once_with(Bucket=expected_bucket_name)
