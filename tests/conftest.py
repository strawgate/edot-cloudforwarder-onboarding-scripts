"""Pytest configuration and fixtures."""

import pytest


@pytest.fixture
def sample_flow_log():
    """Sample VPC Flow Log response."""
    return {
        "FlowLogId": "fl-abc123",
        "ResourceId": "vpc-xyz789",
        "LogDestinationType": "s3",
        "LogDestination": "arn:aws:s3:::my-vpc-logs/flow-logs/",
        "FlowLogStatus": "ACTIVE",
    }


@pytest.fixture
def sample_elb_attributes():
    """Sample ELB attributes response with access logging enabled."""
    return {
        "Attributes": [
            {"Key": "access_logs.s3.enabled", "Value": "true"},
            {"Key": "access_logs.s3.bucket", "Value": "my-elb-logs"},
            {"Key": "access_logs.s3.prefix", "Value": "alb/"},
        ]
    }


@pytest.fixture
def sample_elb_attributes_no_bucket():
    """Sample ELB attributes response with logging enabled but no bucket."""
    return {
        "Attributes": [
            {"Key": "access_logs.s3.enabled", "Value": "true"},
            {"Key": "access_logs.s3.bucket", "Value": ""},
            {"Key": "access_logs.s3.prefix", "Value": ""},
        ]
    }


@pytest.fixture
def sample_load_balancer():
    """Sample ALB description."""
    return {
        "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-alb/abc123",  # noqa: E501
        "LoadBalancerName": "my-alb",
        "Type": "application",
    }
