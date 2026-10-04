"""The documented least-privilege policy must cover every API call a full scan makes."""
import json
from pathlib import Path

from aws_env import build_demo_account
from cloudposture.aws.session import AwsClients
from cloudposture.scanner import run_scan

# API operation -> IAM action, where AWS names them differently
ACTION_ALIASES = {
    ("s3", "ListBuckets"): "s3:ListAllMyBuckets",
    ("s3", "GetBucketEncryption"): "s3:GetEncryptionConfiguration",
    ("s3control", "GetPublicAccessBlock"): "s3:GetAccountPublicAccessBlock",
    ("s3", "GetPublicAccessBlock"): "s3:GetBucketPublicAccessBlock",
}
NO_PERMISSION_NEEDED = {("sts", "GetCallerIdentity")}


def test_policy_covers_all_calls(aws, monkeypatch):
    seen: set[tuple[str, str]] = set()
    original = AwsClients._guarded

    def recording(client):
        client.meta.events.register(
            "before-parameter-build.*.*",
            lambda params=None, model=None, **kw: seen.add((client.meta.service_model.endpoint_prefix
                                                            if client.meta.service_model.service_name != "s3control"
                                                            else "s3control", model.name)),
        )
        return original(client)

    monkeypatch.setattr(AwsClients, "_guarded", staticmethod(recording))
    build_demo_account()
    run_scan(aws)

    doc = json.loads((Path(__file__).resolve().parents[1] / "docs" / "iam-policy.json").read_text())
    allowed = {a for st in doc["Statement"] for a in st["Action"]}
    needed = set()
    for svc, op in seen:
        if (svc, op) in NO_PERMISSION_NEEDED:
            continue
        svc = {"monitoring": "cloudwatch"}.get(svc, svc)
        needed.add(ACTION_ALIASES.get((svc, op), f"{svc}:{op}"))
    assert seen, "no API calls recorded"
    assert needed <= allowed, f"policy is missing: {sorted(needed - allowed)}"
