"""S3 checks (read-only: list buckets, get public-access-block/ACL/policy/encryption)."""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

from botocore.exceptions import ClientError

from cloudposture.checks.base import FindingFactory, ScanContext, check, error_code
from cloudposture.models import Finding, Severity

log = logging.getLogger(__name__)
SVC = "S3"
PAB_KEYS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
PUBLIC_GRANTEES = {
    "http://acs.amazonaws.com/groups/global/AllUsers": "AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers": "AuthenticatedUsers",
}


def _buckets(ctx: ScanContext) -> list[str]:
    return ctx.memo("buckets", lambda: sorted(b["Name"] for b in ctx.client("s3").list_buckets()["Buckets"]))


def _bucket_client(ctx: ScanContext, bucket: str) -> Any:
    def region() -> str:
        loc = ctx.client("s3").get_bucket_location(Bucket=bucket).get("LocationConstraint")
        return {None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(loc, loc)

    return ctx.client("s3", ctx.memo(f"bucket-region:{bucket}", region))


def _per_bucket(ctx: ScanContext, f: FindingFactory, fn: Callable[[Any, str], Finding]) -> list[Finding]:
    """Evaluate each bucket; one failing bucket yields an ERROR finding, not a failed scan."""
    buckets = _buckets(ctx)
    if not buckets:
        return [f.not_applicable("account", "No S3 buckets in this account")]
    out = []
    for name in buckets:
        try:
            out.append(fn(_bucket_client(ctx, name), name))
        except ClientError as exc:
            log.warning("%s failed for bucket %s: %s", f.spec.id, name, exc)
            out.append(f.error(name, error_code(exc)))
    return out


def _pab_state(cfg: dict[str, bool] | None) -> tuple[bool, str]:
    if cfg is None:
        return False, "No public access block configured"
    missing = [k for k in PAB_KEYS if not cfg.get(k)]
    return (not missing), ("All 4 settings enabled" if not missing else f"Disabled: {', '.join(missing)}")


@check(
    id="S3-001", service=SVC, severity=Severity.MEDIUM,
    title="Account-level S3 Block Public Access is fully enabled",
    description="The account-level setting is a guardrail that overrides bucket-level configuration for every bucket.",
    expected="All four account-level Block Public Access settings are enabled",
    remediation=["S3 console > Block Public Access settings for this account > Edit > enable all four settings."],
)
def account_pab(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    try:
        cfg = ctx.client("s3control").get_public_access_block(AccountId=ctx.account_id)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
            raise
        cfg = None
    ok, state = _pab_state(cfg)
    return [f.evaluate(ok, f"account/{ctx.account_id}", state)]


@check(
    id="S3-002", service=SVC, severity=Severity.HIGH,
    title="Bucket-level Block Public Access is fully enabled",
    description="Without bucket-level blocks, a permissive ACL or bucket policy can expose data publicly.",
    expected="All four Block Public Access settings are enabled on the bucket",
    remediation=["S3 > bucket > Permissions > Block public access (bucket settings) > Edit > enable all four settings."],
)
def bucket_pab(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(client: Any, name: str) -> Finding:
        try:
            cfg = client.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
        except ClientError as exc:
            if error_code(exc) != "NoSuchPublicAccessBlockConfiguration":
                raise
            cfg = None
        ok, state = _pab_state(cfg)
        return f.evaluate(ok, name, state)

    return _per_bucket(ctx, f, run)


@check(
    id="S3-003", service=SVC, severity=Severity.CRITICAL,
    title="Bucket is not publicly accessible via policy or ACL",
    description=(
        "Evaluates the bucket policy (AWS policy-status analysis) and ACL grants to AllUsers/AuthenticatedUsers. "
        "Reports the configured access, before Block Public Access is applied."
    ),
    expected="No public bucket policy and no ACL grants to AllUsers or AuthenticatedUsers",
    remediation=[
        "Remove ACL grants to 'Everyone' / 'Authenticated users' (Permissions > ACL).",
        "Restrict bucket policy principals/conditions; enable Block Public Access.",
        "Serve intended-public content through CloudFront with Origin Access Control instead.",
    ],
)
def bucket_not_public(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(client: Any, name: str) -> Finding:
        reasons = []
        try:
            if client.get_bucket_policy_status(Bucket=name)["PolicyStatus"].get("IsPublic", False):
                reasons.append("bucket policy allows public access")
        except ClientError as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
        for grant in client.get_bucket_acl(Bucket=name)["Grants"]:
            uri = grant.get("Grantee", {}).get("URI")
            if uri in PUBLIC_GRANTEES:
                reasons.append(f"ACL grants {grant['Permission']} to {PUBLIC_GRANTEES[uri]}")
        return f.evaluate(not reasons, name, "; ".join(reasons) or "Not public by policy or ACL")

    return _per_bucket(ctx, f, run)


@check(
    id="S3-004", service=SVC, severity=Severity.MEDIUM,
    title="Bucket has default encryption configured",
    description="Default encryption ensures every new object is encrypted at rest (SSE-S3 is applied automatically by AWS to new buckets since Jan 2023).",
    expected="Default server-side encryption is configured (SSE-S3 or SSE-KMS)",
    remediation=["S3 > bucket > Properties > Default encryption > Edit; choose SSE-S3 or SSE-KMS (KMS for key-level audit and control)."],
)
def bucket_encryption(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(client: Any, name: str) -> Finding:
        try:
            rules = client.get_bucket_encryption(Bucket=name)["ServerSideEncryptionConfiguration"]["Rules"]
        except ClientError as exc:
            if error_code(exc) != "ServerSideEncryptionConfigurationNotFoundError":
                raise
            return f.failed(name, "No default encryption configured")
        algos = sorted({r["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"] for r in rules})
        return f.passed(name, f"Default encryption: {', '.join(algos)}")

    return _per_bucket(ctx, f, run)


def denies_insecure_transport(policy: dict[str, Any]) -> bool:
    """True if a statement denies all principals when aws:SecureTransport is false."""
    stmts = policy.get("Statement", [])
    for s in stmts if isinstance(stmts, list) else [stmts]:
        if s.get("Effect") != "Deny":
            continue
        principal = s.get("Principal")
        if principal not in ("*", {"AWS": "*"}):
            continue
        cond = s.get("Condition", {})
        for op in ("Bool", "BoolIfExists"):
            val = cond.get(op, {}).get("aws:SecureTransport")
            if str(val).lower() == "false":
                return True
    return False


@check(
    id="S3-005", service=SVC, severity=Severity.MEDIUM,
    title="Bucket policy denies non-TLS (HTTP) requests",
    description="Without an aws:SecureTransport deny, clients can read/write objects over unencrypted HTTP.",
    expected="Bucket policy contains a Deny for Principal * when aws:SecureTransport is false",
    remediation=[
        'Add a bucket policy statement: Effect Deny, Principal "*", Action "s3:*", Resource bucket ARN and bucket ARN/*, '
        'Condition {"Bool": {"aws:SecureTransport": "false"}}.'
    ],
)
def bucket_tls_only(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(client: Any, name: str) -> Finding:
        try:
            policy = json.loads(client.get_bucket_policy(Bucket=name)["Policy"])
        except ClientError as exc:
            if error_code(exc) != "NoSuchBucketPolicy":
                raise
            return f.failed(name, "No bucket policy; HTTP requests are allowed")
        ok = denies_insecure_transport(policy)
        return f.evaluate(ok, name, "HTTP requests denied" if ok else "Policy does not deny HTTP requests")

    return _per_bucket(ctx, f, run)
