"""IAM checks. All data comes from read-only IAM APIs (credential report, account summary, policies)."""
from __future__ import annotations

import csv
import io
import logging
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from cloudposture.checks.base import FindingFactory, ScanContext, check, error_code
from cloudposture.models import Finding, Severity

log = logging.getLogger(__name__)
SVC = "IAM"
ROOT = "<root_account>"
_NO_VALUE = {"N/A", "no_information", "not_supported", ""}


# --------------------------------------------------------------------------- helpers
def _parse_ts(value: str | None) -> datetime | None:
    if value is None or value in _NO_VALUE:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _days_since(ts: datetime | None, now: datetime) -> int | None:
    return None if ts is None else (now - ts).days


def _now() -> datetime:
    return datetime.now(timezone.utc)


def credential_report(ctx: ScanContext) -> list[dict[str, str]]:
    """Fetch (generating if needed) and parse the IAM credential report. Memoised per scan."""

    def fetch() -> list[dict[str, str]]:
        iam = ctx.client("iam")
        for _ in range(ctx.config.credential_report_max_polls):
            try:
                content = iam.get_credential_report()["Content"]
                return list(csv.DictReader(io.StringIO(content.decode("utf-8"))))
            except ClientError as exc:
                if error_code(exc) not in {"ReportNotPresent", "ReportExpired", "ReportInProgress"}:
                    raise
                if error_code(exc) != "ReportInProgress":
                    iam.generate_credential_report()
                time.sleep(ctx.config.credential_report_poll_seconds)
        raise TimeoutError("IAM credential report was not ready in time")

    return ctx.memo("credential_report", fetch)


def account_summary(ctx: ScanContext) -> dict[str, int]:
    return ctx.memo("account_summary", lambda: ctx.client("iam").get_account_summary()["SummaryMap"])


def _users(ctx: ScanContext) -> list[dict[str, str]]:
    return [r for r in credential_report(ctx) if r["user"] != ROOT]


def _access_keys(row: dict[str, str]):
    """Yield (key_number, row) for each *active* key in a credential-report row."""
    for n in (1, 2):
        if row.get(f"access_key_{n}_active") == "true":
            yield n


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


# --------------------------------------------------------------------------- root account
@check(
    id="IAM-001", service=SVC, severity=Severity.CRITICAL,
    title="MFA is enabled for the root user",
    description="The root user has unrestricted access to the account. Without MFA, a leaked password gives full account takeover.",
    expected="Root user has an MFA device registered",
    remediation=[
        "Sign in as the root user and open Security credentials.",
        "Under Multi-factor authentication (MFA), choose Assign MFA device and complete enrolment (prefer a hardware/FIDO2 key).",
        "Store the root credentials and recovery material offline; use the root user only for tasks that require it.",
    ],
)
def root_mfa(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    enabled = account_summary(ctx).get("AccountMFAEnabled") == 1
    return [f.evaluate(enabled, ROOT, "Root MFA is enabled" if enabled else "Root MFA is NOT enabled")]


@check(
    id="IAM-002", service=SVC, severity=Severity.CRITICAL,
    title="No access keys exist for the root user",
    description="Root access keys are long-lived credentials with unrestricted privileges and cannot be scoped down.",
    expected="No root access keys",
    remediation=[
        "Sign in as the root user, open Security credentials > Access keys.",
        "Make each root access key inactive, confirm nothing breaks, then delete it.",
        "Use IAM roles / IAM Identity Center for programmatic access instead.",
    ],
)
def root_access_keys(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    count = account_summary(ctx).get("AccountAccessKeysPresent", 0)
    return [f.evaluate(count == 0, ROOT, f"{count} root access key(s) present")]


@check(
    id="IAM-003", service=SVC, severity=Severity.MEDIUM,
    title="Root user does not use a virtual MFA device",
    description=(
        "CIS recommends a hardware MFA device for root. The API exposes virtual MFA devices by serial number "
        "but cannot distinguish a hardware token from a FIDO2/passkey, so PASS means 'MFA present and not virtual'."
    ),
    expected="Root MFA is a hardware / FIDO2 device (not a virtual authenticator app)",
    remediation=[
        "Sign in as root > Security credentials > MFA.",
        "Remove the virtual MFA device and register a hardware TOTP token or FIDO2 security key.",
    ],
)
def root_hardware_mfa(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    if account_summary(ctx).get("AccountMFAEnabled") != 1:
        return [f.failed(ROOT, "Root MFA is not enabled at all")]
    devices = ctx.client("iam").get_paginator("list_virtual_mfa_devices")
    virtual = [
        d for page in devices.paginate(AssignmentStatus="Assigned")
        for d in page["VirtualMFADevices"] if d["SerialNumber"].endswith(":mfa/root-account-mfa-device")
    ]
    if virtual:
        return [f.failed(ROOT, "Root uses a virtual MFA device")]
    return [f.passed(ROOT, "Root MFA is enabled and is not a virtual device (hardware/FIDO assumed)")]


# --------------------------------------------------------------------------- users
@check(
    id="IAM-004", service=SVC, severity=Severity.HIGH,
    title="MFA is enabled for all IAM users with a console password",
    description="Console users without MFA are exposed to password phishing, reuse and brute force.",
    expected="Every IAM user with a console password has MFA active",
    remediation=[
        "IAM > Users > select the user > Security credentials > Assign MFA device.",
        "Better: remove IAM console users and federate through IAM Identity Center with enforced MFA.",
    ],
)
def users_mfa(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    rows = [r for r in _users(ctx) if r["password_enabled"] == "true"]
    if not rows:
        return [f.not_applicable("account", "No IAM users with a console password")]
    return [
        f.evaluate(r["mfa_active"] == "true", r["user"],
                   "MFA active" if r["mfa_active"] == "true" else "Console password set but no MFA")
        for r in rows
    ]


@check(
    id="IAM-005", service=SVC, severity=Severity.MEDIUM,
    title="Active access keys are rotated within 90 days",
    description="Long-lived access keys increase the window in which a leaked key can be abused.",
    expected="Every active access key was created/rotated within the configured maximum age (default 90 days)",
    remediation=[
        "Create a second key for the user, update the application to use it, and verify.",
        "Deactivate then delete the old key.",
        "Prefer IAM roles with temporary credentials so no long-lived key exists.",
    ],
)
def key_rotation(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    now, limit = _now(), ctx.config.max_key_age_days
    out = []
    for r in _users(ctx):
        for n in _access_keys(r):
            age = _days_since(_parse_ts(r.get(f"access_key_{n}_last_rotated")), now)
            out.append(f.evaluate(age is not None and age <= limit, f"{r['user']}/access_key_{n}",
                                  f"Key is {age} days old (max {limit})"))
    return out or [f.not_applicable("account", "No active IAM user access keys")]


@check(
    id="IAM-006", service=SVC, severity=Severity.MEDIUM,
    title="Credentials unused for 45+ days are disabled",
    description="Dormant passwords and access keys are rarely monitored and are prime targets for takeover.",
    expected="No active password or access key has gone unused longer than the configured maximum (default 45 days)",
    remediation=[
        "Confirm the credential is no longer needed with its owner.",
        "Deactivate the access key / remove the console password, or delete the IAM user.",
    ],
)
def unused_credentials(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    now, limit = _now(), ctx.config.max_unused_days
    out = []
    for r in _users(ctx):
        stale: list[str] = []
        evaluated = False
        if r["password_enabled"] == "true":
            evaluated = True
            last = _parse_ts(r["password_last_used"]) or _parse_ts(r["password_last_changed"]) or _parse_ts(r["user_creation_time"])
            d = _days_since(last, now)
            if d is not None and d > limit:
                stale.append(f"console password unused {d}d")
        for n in _access_keys(r):
            evaluated = True
            last = _parse_ts(r.get(f"access_key_{n}_last_used_date")) or _parse_ts(r.get(f"access_key_{n}_last_rotated"))
            d = _days_since(last, now)
            if d is not None and d > limit:
                stale.append(f"access key {n} unused {d}d")
        if evaluated:
            out.append(f.evaluate(not stale, r["user"], "; ".join(stale) or f"All credentials used within {limit} days"))
    return out or [f.not_applicable("account", "No IAM users with active credentials")]


@check(
    id="IAM-009", service=SVC, severity=Severity.LOW,
    title="Each IAM user has at most one active access key",
    description="Multiple active keys per user widen the attack surface and often indicate skipped rotation clean-up.",
    expected="At most one active access key per IAM user",
    remediation=["Identify which key is in use (last-used date), then deactivate and delete the other."],
)
def one_active_key(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    out = []
    for r in _users(ctx):
        n = len(list(_access_keys(r)))
        if n:
            out.append(f.evaluate(n <= 1, r["user"], f"{n} active access key(s)"))
    return out or [f.not_applicable("account", "No IAM users with active access keys")]


# --------------------------------------------------------------------------- password policy
def _password_policy(ctx: ScanContext) -> dict[str, Any] | None:
    def fetch():
        try:
            return ctx.client("iam").get_account_password_policy()["PasswordPolicy"]
        except ClientError as exc:
            if error_code(exc) == "NoSuchEntity":
                return None
            raise

    return ctx.memo("password_policy", fetch)


@check(
    id="IAM-007", service=SVC, severity=Severity.MEDIUM,
    title="Password policy requires a minimum length of 14",
    description="Short passwords are easy to brute-force. Without a custom policy AWS defaults to 8 characters.",
    expected="Account password policy minimum length >= 14 (configurable)",
    remediation=["IAM > Account settings > Password policy > Edit, set minimum password length to 14 or more."],
)
def password_length(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    policy, need = _password_policy(ctx), ctx.config.min_password_length
    if policy is None:
        return [f.failed("account-password-policy", f"No custom password policy (AWS default minimum is 8)")]
    length = policy.get("MinimumPasswordLength", 0)
    return [f.evaluate(length >= need, "account-password-policy", f"Minimum length is {length} (required {need})")]


@check(
    id="IAM-008", service=SVC, severity=Severity.MEDIUM,
    title="Password policy prevents reuse of the last 24 passwords",
    description="Allowing reuse undermines rotation: users cycle back to compromised passwords.",
    expected="Password reuse prevention >= 24 (configurable)",
    remediation=["IAM > Account settings > Password policy > Edit, enable 'Prevent password reuse' with 24 remembered passwords."],
)
def password_reuse(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    policy, need = _password_policy(ctx), ctx.config.password_reuse_prevention
    if policy is None:
        return [f.failed("account-password-policy", "No custom password policy (reuse prevention not set)")]
    n = policy.get("PasswordReusePrevention", 0)
    return [f.evaluate(n >= need, "account-password-policy", f"Remembers {n} previous passwords (required {need})")]


# --------------------------------------------------------------------------- permissions
def _is_full_admin(document: dict[str, Any]) -> bool:
    for stmt in _as_list(document.get("Statement", [])):
        if stmt.get("Effect") != "Allow" or "NotAction" in stmt or "NotResource" in stmt:
            continue
        if "*" in _as_list(stmt.get("Action", [])) and "*" in _as_list(stmt.get("Resource", [])):
            return True
    return False


@check(
    id="IAM-010", service=SVC, severity=Severity.HIGH,
    title="No attached customer-managed policy grants full \"*:*\" admin access",
    description=(
        "Policies allowing Action '*' on Resource '*' violate least privilege. Scope: customer-managed policies "
        "that are attached to at least one identity (AWS-managed AdministratorAccess is not evaluated)."
    ),
    expected="No attached customer-managed policy allows Action \"*\" on Resource \"*\"",
    remediation=[
        "Replace the policy with scoped permissions (use IAM Access Analyzer policy generation from CloudTrail activity).",
        "Detach the over-permissive policy once replacements are in place.",
    ],
)
def admin_policies(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    iam = ctx.client("iam")
    out = []
    for page in iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=True):
        for p in page["Policies"]:
            doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
            admin = _is_full_admin(doc)
            out.append(f.evaluate(not admin, p["PolicyName"], "Allows *:* (full admin)" if admin else "No full-admin statement"))
    return out or [f.not_applicable("account", "No attached customer-managed policies")]


@check(
    id="IAM-011", service=SVC, severity=Severity.LOW,
    title="IAM users receive permissions only through groups",
    description="Direct user policies are hard to audit and tend to accumulate; group/role-based access is reviewable.",
    expected="No managed or inline policies attached directly to IAM users",
    remediation=[
        "Create a group per job function and attach the policies to it.",
        "Add the user to the group, then detach/delete the user's direct policies.",
    ],
)
def user_direct_policies(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    iam = ctx.client("iam")
    out = []
    for r in _users(ctx):
        name = r["user"]
        attached = [p["PolicyName"] for pg in iam.get_paginator("list_attached_user_policies").paginate(UserName=name)
                    for p in pg["AttachedPolicies"]]
        inline = [n for pg in iam.get_paginator("list_user_policies").paginate(UserName=name) for n in pg["PolicyNames"]]
        direct = attached + [f"inline:{n}" for n in inline]
        out.append(f.evaluate(not direct, name, f"Direct policies: {', '.join(direct)}" if direct else "No direct policies"))
    return out or [f.not_applicable("account", "No IAM users")]
