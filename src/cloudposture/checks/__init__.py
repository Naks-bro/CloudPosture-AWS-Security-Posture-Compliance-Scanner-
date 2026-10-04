"""Importing this package registers every check in REGISTRY."""
from cloudposture.checks import cloudtrail, ec2, iam, s3  # noqa: F401
from cloudposture.checks.base import REGISTRY, CheckSpec, RegisteredCheck, ScanContext

__all__ = ["REGISTRY", "CheckSpec", "RegisteredCheck", "ScanContext"]
