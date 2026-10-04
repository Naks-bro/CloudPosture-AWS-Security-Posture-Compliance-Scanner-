import boto3
import pytest
from moto import mock_aws

from cloudposture.aws.session import AwsClients, ReadOnlyViolation, is_read_only_operation


@pytest.mark.parametrize("op", ["GetAccountSummary", "ListUsers", "DescribeSecurityGroups", "GenerateCredentialReport"])
def test_reads_allowed(op):
    assert is_read_only_operation(op)


@pytest.mark.parametrize("op", ["CreateUser", "DeleteBucket", "PutBucketPolicy", "AuthorizeSecurityGroupIngress",
                                "UpdateAccountPasswordPolicy", "StopLogging", "RunInstances"])
def test_writes_blocked(op):
    assert not is_read_only_operation(op)


def test_guard_blocks_mutations_on_real_clients(aws):
    clients = AwsClients(aws)
    with pytest.raises(ReadOnlyViolation):
        clients.client("iam").create_user(UserName="should-never-exist")
    with pytest.raises(ReadOnlyViolation):
        clients.client("s3").create_bucket(Bucket="should-never-exist")
    with pytest.raises(ReadOnlyViolation):
        clients.client("ec2").run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1)
    # and nothing was created
    assert boto3.client("iam").list_users()["Users"] == []
    assert boto3.client("s3").list_buckets()["Buckets"] == []


def test_reads_work(aws):
    assert AwsClients(aws).account_id
