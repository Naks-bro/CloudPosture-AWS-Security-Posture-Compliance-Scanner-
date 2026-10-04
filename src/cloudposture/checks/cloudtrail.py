"""CloudTrail checks. Trails are discovered once (incl. multi-region shadow trails) and de-duplicated."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cloudposture.checks.base import FindingFactory, ScanContext, check
from cloudposture.models import Finding, Severity

SVC = "CloudTrail"


def _trails(ctx: ScanContext) -> list[dict[str, Any]]:
    def fetch() -> list[dict[str, Any]]:
        resp = ctx.client("cloudtrail").describe_trails(includeShadowTrails=True)
        unique = {t["TrailARN"]: t for t in resp["trailList"]}  # shadow trails repeat the same ARN
        return sorted(unique.values(), key=lambda t: t["Name"])

    return ctx.memo("trails", fetch)


def _status(ctx: ScanContext, trail: dict[str, Any]) -> dict[str, Any]:
    """Trail status must be queried in the trail's home region."""
    return ctx.memo(
        f"trail-status:{trail['TrailARN']}",
        lambda: ctx.client("cloudtrail", trail.get("HomeRegion") or ctx.config.home_region).get_trail_status(
            Name=trail["TrailARN"]
        ),
    )


def _captures_all_management_events(ctx: ScanContext, trail: dict[str, Any]) -> bool:
    """True if the trail records read+write management events."""
    client = ctx.client("cloudtrail", trail.get("HomeRegion") or ctx.config.home_region)
    resp = client.get_event_selectors(TrailName=trail["TrailARN"])
    for sel in resp.get("EventSelectors", []):
        if sel.get("IncludeManagementEvents") and sel.get("ReadWriteType") == "All":
            return True
    for adv in resp.get("AdvancedEventSelectors", []):
        fields = {fs["Field"]: fs for fs in adv.get("FieldSelectors", [])}
        cat = fields.get("eventCategory", {}).get("Equals", [])
        # Only an unrestricted management selector qualifies (no readOnly/eventName/etc. filters)
        if "Management" in cat and set(fields) <= {"eventCategory"}:
            return True
    return False


def _no_trails(f: FindingFactory) -> list[Finding]:
    return [f.not_applicable("account", "No CloudTrail trails exist (see CT-001)")]


@check(
    id="CT-001", service=SVC, severity=Severity.HIGH,
    title="A multi-region CloudTrail trail is enabled and logging management events",
    description=(
        "Without an active multi-region trail, API activity in some regions is not recorded, "
        "leaving no audit trail for incident response."
    ),
    expected="At least one multi-region trail is logging and records read+write management events",
    remediation=[
        "CloudTrail > Trails > Create trail with 'Apply trail to all regions' enabled.",
        "Record management events (Read and Write) and make sure logging is started.",
        "In AWS Organizations, an organization trail satisfies this for all member accounts.",
    ],
)
def multi_region_trail(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    notes, good = [], []
    for t in _trails(ctx):
        if not t.get("IsMultiRegionTrail"):
            notes.append(f"{t['Name']}: single-region")
        elif not _status(ctx, t).get("IsLogging"):
            notes.append(f"{t['Name']}: logging is off")
        elif not _captures_all_management_events(ctx, t):
            notes.append(f"{t['Name']}: does not capture all management events")
        else:
            good.append(t["Name"])
    if good:
        return [f.passed("account", f"Compliant multi-region trail(s): {', '.join(good)}")]
    return [f.failed("account", "; ".join(notes) or "No CloudTrail trails exist")]


@check(
    id="CT-002", service=SVC, severity=Severity.MEDIUM,
    title="CloudTrail log file validation is enabled",
    description="Digest files let you prove that log files were not modified or deleted after delivery.",
    expected="LogFileValidationEnabled = true",
    remediation=["CloudTrail > Trails > trail > General details > Edit > enable 'Log file validation'."],
)
def log_validation(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    trails = _trails(ctx)
    if not trails:
        return _no_trails(f)
    return [
        f.evaluate(bool(t.get("LogFileValidationEnabled")), t["Name"],
                   "Enabled" if t.get("LogFileValidationEnabled") else "Disabled", t.get("HomeRegion", "global"))
        for t in trails
    ]


@check(
    id="CT-003", service=SVC, severity=Severity.LOW,
    title="CloudTrail trail is integrated with CloudWatch Logs",
    description="CloudWatch Logs integration enables near-real-time alerting on suspicious API activity. Delivery must be recent (within 24h).",
    expected="Trail delivers to a CloudWatch Logs group and the latest delivery is < 24 hours old",
    remediation=[
        "CloudTrail > trail > CloudWatch Logs > Edit > enable and select/create a log group and IAM role.",
        "Add metric filters and alarms for the CIS monitoring controls (root usage, console sign-in without MFA, etc.).",
    ],
)
def cloudwatch_integration(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    trails = _trails(ctx)
    if not trails:
        return _no_trails(f)
    out = []
    now = datetime.now(timezone.utc)
    for t in trails:
        region = t.get("HomeRegion", "global")
        if not t.get("CloudWatchLogsLogGroupArn"):
            out.append(f.failed(t["Name"], "No CloudWatch Logs log group configured", region))
            continue
        last = _status(ctx, t).get("LatestCloudWatchLogsDeliveryTime")
        if last is None:
            out.append(f.failed(t["Name"], "Log group configured but no delivery recorded", region))
        else:
            age_h = (now - last).total_seconds() / 3600
            out.append(f.evaluate(age_h < 24, t["Name"], f"Last CloudWatch delivery {age_h:.1f}h ago", region))
    return out


@check(
    id="CT-004", service=SVC, severity=Severity.MEDIUM,
    title="CloudTrail logs are encrypted with a KMS key",
    description="SSE-KMS adds key-level access control and auditing on top of default S3 encryption of log files.",
    expected="Trail has a KmsKeyId configured",
    remediation=["CloudTrail > trail > General details > Edit > enable 'Log file SSE-KMS encryption' with a customer-managed key."],
)
def kms_encryption(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    trails = _trails(ctx)
    if not trails:
        return _no_trails(f)
    return [
        f.evaluate(bool(t.get("KmsKeyId")), t["Name"], "SSE-KMS enabled" if t.get("KmsKeyId") else "No KMS key configured",
                   t.get("HomeRegion", "global"))
        for t in trails
    ]
