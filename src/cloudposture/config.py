"""Configuration: environment variables (optionally via a local .env) -> ScanConfig.

Credentials are never read or stored here. boto3's standard credential chain
(AWS profile, SSO, environment, instance role) is the only credential source.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> None:
    """Minimal .env loader. Existing environment variables always win."""
    p = Path(path)
    if not p.is_file():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip().strip("'\"")
        if value:
            os.environ.setdefault(key.strip(), value)


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


@dataclass
class ScanConfig:
    profile: str | None = None
    home_region: str = "us-east-1"
    regions: list[str] = field(default_factory=list)  # empty = all enabled regions
    role_arn: str | None = None
    max_key_age_days: int = 90
    max_unused_days: int = 45
    min_password_length: int = 14
    password_reuse_prevention: int = 24
    credential_report_poll_seconds: float = 2.0
    credential_report_max_polls: int = 15

    @classmethod
    def from_env(cls) -> "ScanConfig":
        regions = [r.strip() for r in os.environ.get("CLOUDPOSTURE_REGIONS", "").split(",") if r.strip()]
        return cls(
            profile=os.environ.get("CLOUDPOSTURE_PROFILE") or None,
            home_region=os.environ.get("CLOUDPOSTURE_HOME_REGION")
            or os.environ.get("AWS_DEFAULT_REGION")
            or "us-east-1",
            regions=regions,
            role_arn=os.environ.get("CLOUDPOSTURE_ROLE_ARN") or None,
            max_key_age_days=_int("CLOUDPOSTURE_MAX_KEY_AGE_DAYS", 90),
            max_unused_days=_int("CLOUDPOSTURE_MAX_UNUSED_DAYS", 45),
            min_password_length=_int("CLOUDPOSTURE_MIN_PASSWORD_LENGTH", 14),
            password_reuse_prevention=_int("CLOUDPOSTURE_PASSWORD_REUSE", 24),
        )
