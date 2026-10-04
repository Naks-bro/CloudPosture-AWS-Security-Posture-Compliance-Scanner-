"""Scan orchestration: select checks, run them in isolation, collect a ScanResult."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from botocore.exceptions import BotoCoreError, ClientError

from cloudposture import __version__
from cloudposture.aws.session import AwsClients, ReadOnlyViolation
from cloudposture.checks import REGISTRY, ScanContext
from cloudposture.checks.base import FindingFactory, error_code
from cloudposture.config import ScanConfig
from cloudposture.models import Finding, ScanMetadata, ScanResult

log = logging.getLogger(__name__)


def select_checks(services: list[str] | None = None, check_ids: list[str] | None = None):
    services_l = {s.lower() for s in services or []}
    ids = {c.upper() for c in check_ids or []}
    unknown = ids - set(REGISTRY)
    if unknown:
        raise ValueError(f"Unknown check id(s): {', '.join(sorted(unknown))}")
    selected = [
        rc for rc in REGISTRY.values()
        if (not services_l or rc.spec.service.lower() in services_l) and (not ids or rc.spec.id in ids)
    ]
    if not selected:
        raise ValueError("No checks match the given filters")
    return sorted(selected, key=lambda rc: rc.spec.id)


def _run_one(rc, ctx: ScanContext) -> list[Finding]:
    """Run one check. A failure becomes an ERROR finding - it never aborts the scan
    and is never reported as a pass."""
    f = FindingFactory(rc.spec)
    try:
        return rc.func(ctx, f)
    except ReadOnlyViolation:
        raise  # programming error: must never be swallowed
    except ClientError as exc:
        code = error_code(exc)
        log.warning("%s: AWS error %s", rc.spec.id, code)
        hint = " (grant the read-only permissions in docs/iam-policy.json)" if "AccessDenied" in code or "Unauthorized" in code else ""
        return [f.error("account", f"{code}{hint}")]
    except (BotoCoreError, TimeoutError, KeyError, ValueError) as exc:
        log.exception("%s failed", rc.spec.id)
        return [f.error("account", f"{type(exc).__name__}: {exc}")]


def run_scan(
    config: ScanConfig,
    services: list[str] | None = None,
    check_ids: list[str] | None = None,
    clients: AwsClients | None = None,
) -> ScanResult:
    checks = select_checks(services, check_ids)
    clients = clients or AwsClients(config)
    ctx = ScanContext(clients=clients, config=config)
    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    account = ctx.account_id
    log.info("Scanning account %s with %d checks", account, len(checks))

    findings: list[Finding] = []
    notes: list[str] = []
    for rc in checks:
        log.info("Running %s %s", rc.spec.id, rc.spec.title)
        findings.extend(_run_one(rc, ctx))
    needs_regions = any(rc.spec.service == "EC2" for rc in checks)
    regions = ctx.regions if needs_regions else []
    if any(x.status.value == "ERROR" for x in findings):
        notes.append("Some checks could not be evaluated (status ERROR) and are excluded from scores.")

    meta = ScanMetadata(
        mode="live", account_id=account, regions=regions,
        started_at=started.isoformat(timespec="seconds"),
        duration_seconds=round(time.monotonic() - t0, 2),
        tool_version=__version__, notes=notes,
    )
    return ScanResult(findings=findings, metadata=meta)
