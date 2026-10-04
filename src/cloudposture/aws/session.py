"""Reusable AWS session/client handling with a hard read-only guard.

Every client created here is wrapped by :func:`read_only_guard`, which raises
before the request is built if the API operation is not a read. This makes the
"scanner never modifies AWS" guarantee enforceable in code, not just documented.
"""
from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.config import Config

from cloudposture import __version__
from cloudposture.config import ScanConfig

log = logging.getLogger(__name__)

READ_ONLY_PREFIXES = ("Get", "List", "Describe")
# Explicit exceptions. GenerateCredentialReport only (re)builds the IAM credential
# report snapshot - it changes no resource. AssumeRole is used only if the user
# supplies CLOUDPOSTURE_ROLE_ARN.
EXPLICITLY_ALLOWED = frozenset({"GenerateCredentialReport", "AssumeRole"})


class ReadOnlyViolation(RuntimeError):
    """Raised when code attempts a non-read AWS API call."""


def is_read_only_operation(operation_name: str) -> bool:
    return operation_name.startswith(READ_ONLY_PREFIXES) or operation_name in EXPLICITLY_ALLOWED


def read_only_guard(params: Any = None, model: Any = None, **kwargs: Any) -> None:
    """botocore ``before-parameter-build`` hook."""
    name = getattr(model, "name", "")
    if not is_read_only_operation(name):
        raise ReadOnlyViolation(f"Blocked non-read-only AWS API call: {name}")


class AwsClients:
    """Creates and caches boto3 clients (per service/region) with the guard attached."""

    def __init__(self, config: ScanConfig, session: boto3.Session | None = None):
        self.config = config
        self._boto_config = Config(
            retries={"max_attempts": 8, "mode": "adaptive"},
            user_agent_extra=f"cloudposture/{__version__}",
            connect_timeout=10,
            read_timeout=60,
        )
        self._session = session or self._build_session()
        self._clients: dict[tuple[str, str], Any] = {}
        self._account_id: str | None = None

    # -- session -----------------------------------------------------------
    def _build_session(self) -> boto3.Session:
        base = boto3.Session(profile_name=self.config.profile, region_name=self.config.home_region)
        if not self.config.role_arn:
            return base
        sts = self._guarded(base.client("sts", config=self._boto_config))
        creds = sts.assume_role(RoleArn=self.config.role_arn, RoleSessionName="cloudposture-scan")[
            "Credentials"
        ]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.config.home_region,
        )

    @staticmethod
    def _guarded(client: Any) -> Any:
        client.meta.events.register("before-parameter-build.*.*", read_only_guard)
        return client

    # -- public API --------------------------------------------------------
    def client(self, service: str, region: str | None = None) -> Any:
        region = region or self.config.home_region
        key = (service, region)
        if key not in self._clients:
            self._clients[key] = self._guarded(
                self._session.client(service, region_name=region, config=self._boto_config)
            )
        return self._clients[key]

    @property
    def account_id(self) -> str:
        if self._account_id is None:
            self._account_id = self.client("sts").get_caller_identity()["Account"]
        return self._account_id

    def enabled_regions(self) -> list[str]:
        """Regions enabled for the account (opt-in regions that are disabled are excluded)."""
        resp = self.client("ec2").describe_regions(AllRegions=False)
        return sorted(r["RegionName"] for r in resp["Regions"])
