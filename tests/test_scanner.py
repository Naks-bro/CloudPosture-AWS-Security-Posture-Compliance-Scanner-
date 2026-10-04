import boto3
import pytest
from botocore.exceptions import ClientError

from aws_env import build_insecure_account, build_secure_account
from cloudposture.aws.session import AwsClients
from cloudposture.checks import REGISTRY
from cloudposture.checks.base import FindingFactory, ScanContext
from cloudposture.models import Status
from cloudposture.scanner import _run_one, run_scan, select_checks
from cloudposture.scoring import summarize


def test_select_checks_filters():
    assert {rc.spec.service for rc in select_checks(services=["s3"])} == {"S3"}
    assert [rc.spec.id for rc in select_checks(check_ids=["iam-001", "S3-001"])] == ["IAM-001", "S3-001"]
    with pytest.raises(ValueError):
        select_checks(check_ids=["NOPE-1"])


def test_full_scan_insecure_account(aws):
    build_insecure_account()
    result = run_scan(aws)
    ids = {f.check_id for f in result.findings}
    assert ids == set(REGISTRY), f"checks that produced no finding: {set(REGISTRY) - ids}"
    assert not [f for f in result.findings if f.status is Status.ERROR], \
        [f.current_state for f in result.findings if f.status is Status.ERROR]
    s = summarize(result.findings)
    assert s.failed > s.passed
    assert result.metadata.account_id == "123456789012"
    assert s.severity["CRITICAL"].failed >= 2


def test_secure_account_scores_higher_than_insecure(aws):
    build_secure_account()
    secure = summarize(run_scan(aws).findings)
    assert secure.pass_rate > 50
    assert secure.severity["CRITICAL"].failed == 1  # only root MFA: moto cannot enrol root MFA


def test_scan_never_mutates_account(aws):
    build_insecure_account()
    iam, s3 = boto3.client("iam"), boto3.client("s3")
    before = (sorted(u["UserName"] for u in iam.list_users()["Users"]),
              sorted(b["Name"] for b in s3.list_buckets()["Buckets"]),
              iam.get_account_password_policy()["PasswordPolicy"])
    run_scan(aws)
    after = (sorted(u["UserName"] for u in iam.list_users()["Users"]),
             sorted(b["Name"] for b in s3.list_buckets()["Buckets"]),
             iam.get_account_password_policy()["PasswordPolicy"])
    assert before == after


def test_access_denied_becomes_error_not_pass(aws):
    ctx = ScanContext(AwsClients(aws), aws)
    rc = REGISTRY["IAM-001"]

    def boom(c, f):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetAccountSummary")

    findings = _run_one(type(rc)(rc.spec, boom), ctx)
    assert [f.status for f in findings] == [Status.ERROR]
    assert "AccessDenied" in findings[0].current_state
    assert summarize(findings).pass_rate is None


def test_region_failure_isolated(aws):
    aws.regions = ["us-east-1", "eu-west-1"]
    ctx = ScanContext(AwsClients(aws), aws)
    rc = REGISTRY["EC2-004"]
    real = ctx.client

    def flaky(service, region=None):
        if region == "eu-west-1":
            class Bad:
                def get_ebs_encryption_by_default(self):
                    raise ClientError({"Error": {"Code": "AuthFailure", "Message": "x"}}, "Op")
            return Bad()
        return real(service, region)

    ctx.client = flaky
    out = rc.func(ctx, FindingFactory(rc.spec))
    assert {f.status for f in out} == {Status.FAIL, Status.ERROR}
