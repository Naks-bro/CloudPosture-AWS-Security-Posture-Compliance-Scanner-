import os

import boto3
import pytest
from moto import mock_aws

from cloudposture.aws.session import AwsClients
from cloudposture.checks import ScanContext
from cloudposture.config import ScanConfig

from aws_env import REGION


@pytest.fixture(autouse=True)
def fake_aws_env(monkeypatch):
    """Guarantee tests can never touch a real account."""
    for var in ("AWS_PROFILE", "AWS_SESSION_TOKEN", "CLOUDPOSTURE_PROFILE", "CLOUDPOSTURE_ROLE_ARN"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def config():
    return ScanConfig(home_region=REGION, regions=[REGION], credential_report_poll_seconds=0)


@pytest.fixture
def aws(config):
    with mock_aws():
        yield config


@pytest.fixture
def ctx(aws):
    return ScanContext(clients=AwsClients(aws), config=aws)
