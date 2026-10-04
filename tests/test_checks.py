"""Run each check against moto accounts and against hand-crafted data for time-based logic."""
from datetime import datetime, timedelta, timezone

import pytest

from aws_env import build_insecure_account, build_secure_account
from cloudposture.checks import REGISTRY
from cloudposture.checks.base import FindingFactory
from cloudposture.checks.ec2 import exposed_sources
from cloudposture.checks.iam import _is_full_admin
from cloudposture.checks.s3 import denies_insecure_transport
from cloudposture.models import Status


def run(ctx, check_id):
    rc = REGISTRY[check_id]
    return rc.func(ctx, FindingFactory(rc.spec))


def statuses(findings):
    return {f.resource: f.status for f in findings}


def only(findings):
    assert len(findings) == 1, findings
    return findings[0]


def iso(days_ago):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")


# ----------------------------------------------------------------------------- pure helpers
def test_full_admin_detection():
    assert _is_full_admin({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}})
    assert _is_full_admin({"Statement": [{"Effect": "Allow", "Action": ["s3:*", "*"], "Resource": ["*"]}]})
    assert not _is_full_admin({"Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    assert not _is_full_admin({"Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]})
    assert not _is_full_admin({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::b"}]})


def test_https_only_policy_detection():
    deny = {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "*",
            "Condition": {"Bool": {"aws:SecureTransport": "false"}}}
    assert denies_insecure_transport({"Statement": [deny]})
    assert not denies_insecure_transport({"Statement": [{**deny, "Effect": "Allow"}]})
    assert not denies_insecure_transport({"Statement": [{**deny, "Principal": {"AWS": "arn:aws:iam::1:root"}}]})
    assert not denies_insecure_transport({"Statement": [{**deny, "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]})


@pytest.mark.parametrize("perm,port,expected", [
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, 22, ["0.0.0.0/0"]),
    ({"IpProtocol": "tcp", "FromPort": 0, "ToPort": 65535, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, 3389, ["0.0.0.0/0"]),
    ({"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, 22, ["0.0.0.0/0"]),
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}, 22, ["::/0"]),
    ({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}, 22, []),
    ({"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, 22, []),
    ({"IpProtocol": "udp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}, 22, []),
])
def test_exposed_sources(perm, port, expected):
    assert exposed_sources({"IpPermissions": [perm]}, port) == expected


# ----------------------------------------------------------------------------- IAM time logic
def row(user, **kw):
    base = {"user": user, "password_enabled": "false", "mfa_active": "false", "password_last_used": "N/A",
            "password_last_changed": "N/A", "user_creation_time": iso(400),
            "access_key_1_active": "false", "access_key_1_last_rotated": "N/A", "access_key_1_last_used_date": "N/A",
            "access_key_2_active": "false", "access_key_2_last_rotated": "N/A", "access_key_2_last_used_date": "N/A"}
    base.update(kw)
    return base


def test_key_rotation_boundaries(ctx):
    ctx._cache["credential_report"] = [
        row("fresh", access_key_1_active="true", access_key_1_last_rotated=iso(10)),
        row("edge", access_key_1_active="true", access_key_1_last_rotated=iso(90)),
        row("old", access_key_1_active="true", access_key_1_last_rotated=iso(91)),
        row("inactive-old", access_key_1_active="false", access_key_1_last_rotated=iso(500)),
    ]
    st = statuses(run(ctx, "IAM-005"))
    assert st == {"fresh/access_key_1": Status.PASS, "edge/access_key_1": Status.PASS, "old/access_key_1": Status.FAIL}


def test_unused_credentials(ctx):
    ctx._cache["credential_report"] = [
        row("stale-pw", password_enabled="true", password_last_used=iso(100)),
        row("never-used-key", access_key_1_active="true", access_key_1_last_rotated=iso(60)),
        row("active", password_enabled="true", password_last_used=iso(2),
            access_key_1_active="true", access_key_1_last_rotated=iso(200), access_key_1_last_used_date=iso(3)),
        row("no-creds"),
    ]
    st = statuses(run(ctx, "IAM-006"))
    assert st == {"stale-pw": Status.FAIL, "never-used-key": Status.FAIL, "active": Status.PASS}


def test_mfa_and_two_keys(ctx):
    ctx._cache["credential_report"] = [
        row("a", password_enabled="true", mfa_active="true"),
        row("b", password_enabled="true"),
        row("c", access_key_1_active="true", access_key_2_active="true"),
        row("<root_account>", password_enabled="true"),  # root must be ignored
    ]
    assert statuses(run(ctx, "IAM-004")) == {"a": Status.PASS, "b": Status.FAIL}
    assert statuses(run(ctx, "IAM-009")) == {"c": Status.FAIL}


def test_no_users_is_not_applicable(ctx):
    ctx._cache["credential_report"] = []
    for cid in ("IAM-004", "IAM-005", "IAM-006", "IAM-009", "IAM-011"):
        assert only(run(ctx, cid)).status is Status.NOT_APPLICABLE, cid


# ----------------------------------------------------------------------------- insecure account (moto)
@pytest.fixture
def insecure(ctx):
    build_insecure_account()
    return ctx


def test_iam_insecure(insecure):
    c = insecure
    assert only(run(c, "IAM-001")).status is Status.FAIL
    assert only(run(c, "IAM-002")).status is Status.PASS
    assert only(run(c, "IAM-003")).status is Status.FAIL
    assert statuses(run(c, "IAM-004"))["alice"] is Status.FAIL
    assert statuses(run(c, "IAM-009")) == {"alice": Status.FAIL, "svc-deploy": Status.PASS}
    assert only(run(c, "IAM-007")).status is Status.FAIL
    assert only(run(c, "IAM-008")).status is Status.FAIL
    assert statuses(run(c, "IAM-010")) == {"legacy-admin": Status.FAIL}
    assert statuses(run(c, "IAM-011")) == {"alice": Status.FAIL, "svc-deploy": Status.PASS}


def test_s3_insecure(insecure):
    c = insecure
    assert only(run(c, "S3-001")).status is Status.FAIL
    assert set(statuses(run(c, "S3-002")).values()) == {Status.FAIL}
    assert statuses(run(c, "S3-003"))["acme-public-assets"] is Status.FAIL
    assert statuses(run(c, "S3-003"))["acme-internal-data"] is Status.PASS
    enc = statuses(run(c, "S3-004"))
    assert enc["acme-internal-data"] is Status.PASS
    assert set(statuses(run(c, "S3-005")).values()) == {Status.FAIL}


def test_ec2_insecure(insecure):
    c = insecure
    ssh = {f.resource.split()[0]: f for f in run(c, "EC2-001")}
    assert any(f.status is Status.FAIL and "web-open" in f.resource for f in ssh.values())
    rdp = run(c, "EC2-002")
    bad_rdp = [f for f in rdp if f.status is Status.FAIL]
    assert len(bad_rdp) == 1 and "::/0" in bad_rdp[0].current_state  # v4 rule was a /8, only v6 is world-open
    assert only(run(c, "EC2-004")).status is Status.FAIL
    assert Status.FAIL in {f.status for f in run(c, "EC2-005")}
    assert Status.FAIL in {f.status for f in run(c, "EC2-006")}


def test_cloudtrail_insecure(insecure):
    c = insecure
    assert only(run(c, "CT-001")).status is Status.FAIL
    assert statuses(run(c, "CT-002")) == {"basic-trail": Status.FAIL}
    assert statuses(run(c, "CT-003")) == {"basic-trail": Status.FAIL}
    assert statuses(run(c, "CT-004")) == {"basic-trail": Status.FAIL}


# ----------------------------------------------------------------------------- secure account (moto)
def test_secure_account_passes_targeted_checks(ctx):
    build_secure_account()
    assert only(run(ctx, "IAM-007")).status is Status.PASS
    assert only(run(ctx, "IAM-008")).status is Status.PASS
    assert statuses(run(ctx, "S3-002"))["secure-bucket"] is Status.PASS
    assert statuses(run(ctx, "S3-003"))["secure-bucket"] is Status.PASS
    assert statuses(run(ctx, "S3-004"))["secure-bucket"] is Status.PASS
    assert statuses(run(ctx, "S3-005"))["secure-bucket"] is Status.PASS
    assert only(run(ctx, "EC2-004")).status is Status.PASS
    assert only(run(ctx, "CT-001")).status is Status.PASS
    assert statuses(run(ctx, "CT-002")) == {"org-trail": Status.PASS}
    assert statuses(run(ctx, "CT-004")) == {"org-trail": Status.PASS}


def test_empty_account_edge_cases(ctx):
    assert only(run(ctx, "S3-002")).status is Status.NOT_APPLICABLE
    assert only(run(ctx, "CT-001")).status is Status.FAIL  # no trail at all is a failure, not N/A
    assert only(run(ctx, "CT-002")).status is Status.NOT_APPLICABLE
    assert only(run(ctx, "IAM-010")).status is Status.NOT_APPLICABLE


def test_multi_region_trail_not_logging_or_read_only_fails(ctx):
    import boto3
    build_secure_account()
    ct = boto3.client("cloudtrail", region_name="us-east-1")
    ct.put_event_selectors(TrailName="org-trail", EventSelectors=[
        {"ReadWriteType": "ReadOnly", "IncludeManagementEvents": True, "DataResources": []}])
    assert "management events" in only(run(ctx, "CT-001")).current_state
    ctx._cache.clear()
    ct.put_event_selectors(TrailName="org-trail", EventSelectors=[
        {"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}])
    ct.stop_logging(Name="org-trail")
    assert "logging is off" in only(run(ctx, "CT-001")).current_state
