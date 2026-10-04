"""Builders for fake AWS accounts (moto). Used by tests and scripts/generate_sample_data.py."""
from __future__ import annotations

import json

import boto3

REGION = "us-east-1"
SECOND_REGION = "eu-west-1"


def _sg_rule(port: int, cidr: str = "0.0.0.0/0", v6: str | None = None) -> dict:
    perm = {"IpProtocol": "tcp", "FromPort": port, "ToPort": port, "IpRanges": [{"CidrIp": cidr}]}
    if v6:
        perm["Ipv6Ranges"] = [{"CidrIpv6": v6}]
    return perm


def build_insecure_account() -> None:
    iam = boto3.client("iam", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    ct = boto3.client("cloudtrail", region_name=REGION)

    # IAM: console user w/o MFA, two keys, direct policy, weak password policy, *:* policy
    iam.create_user(UserName="alice")
    iam.create_login_profile(UserName="alice", Password="Sup3rSecret!pw", PasswordResetRequired=False)
    iam.create_access_key(UserName="alice")
    iam.create_access_key(UserName="alice")
    iam.create_user(UserName="svc-deploy")
    iam.create_access_key(UserName="svc-deploy")
    admin = iam.create_policy(
        PolicyName="legacy-admin",
        PolicyDocument=json.dumps({"Version": "2012-10-17",
                                   "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}),
    )["Policy"]["Arn"]
    iam.attach_user_policy(UserName="alice", PolicyArn=admin)
    iam.update_account_password_policy(MinimumPasswordLength=8, PasswordReusePrevention=3)

    # S3: public, unencrypted-by-policy, no PAB
    s3.create_bucket(Bucket="acme-public-assets", ACL="public-read")
    s3.create_bucket(Bucket="acme-internal-data")
    s3.put_bucket_encryption(
        Bucket="acme-internal-data",
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]},
    )

    # EC2: world-open SSH/RDP, unencrypted volume, IMDSv1 instance
    vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.0.1.0/24")["Subnet"]["SubnetId"]
    sg = ec2.create_security_group(GroupName="web-open", Description="demo", VpcId=vpc)["GroupId"]
    ec2.authorize_security_group_ingress(GroupId=sg, IpPermissions=[_sg_rule(22), _sg_rule(3389, "10.0.0.0/8", "::/0")])
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, Encrypted=False)
    ec2.run_instances(ImageId="ami-12345678", MinCount=1, MaxCount=1, SubnetId=subnet,
                      MetadataOptions={"HttpTokens": "optional"})

    # CloudTrail: single-region trail, no validation/KMS/CloudWatch
    s3.create_bucket(Bucket="acme-trail-logs")
    ct.create_trail(Name="basic-trail", S3BucketName="acme-trail-logs", IsMultiRegionTrail=False)


def build_secure_account() -> None:
    iam = boto3.client("iam", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    ct = boto3.client("cloudtrail", region_name=REGION)

    iam.update_account_password_policy(MinimumPasswordLength=14, PasswordReusePrevention=24)

    s3.create_bucket(Bucket="secure-bucket")
    s3.put_public_access_block(
        Bucket="secure-bucket",
        PublicAccessBlockConfiguration={k: True for k in
                                        ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
    )
    s3.put_bucket_encryption(
        Bucket="secure-bucket",
        ServerSideEncryptionConfiguration={"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]},
    )
    s3.put_bucket_policy(Bucket="secure-bucket", Policy=json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Deny", "Principal": "*", "Action": "s3:*",
                       "Resource": ["arn:aws:s3:::secure-bucket", "arn:aws:s3:::secure-bucket/*"],
                       "Condition": {"Bool": {"aws:SecureTransport": "false"}}}],
    }))
    ec2.enable_ebs_encryption_by_default()
    s3.create_bucket(Bucket="secure-trail-logs")
    ct.create_trail(Name="org-trail", S3BucketName="secure-trail-logs", IsMultiRegionTrail=True,
                    EnableLogFileValidation=True, KmsKeyId="alias/aws/cloudtrail")
    ct.put_event_selectors(TrailName="org-trail", EventSelectors=[
        {"ReadWriteType": "All", "IncludeManagementEvents": True, "DataResources": []}])
    ct.start_logging(Name="org-trail")


def build_demo_account() -> None:
    """A realistic mixed-posture fake account for the bundled demo data."""
    build_insecure_account()
    build_secure_account()
    iam = boto3.client("iam", region_name=REGION)
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    iam.create_group(GroupName="developers")
    iam.create_user(UserName="bob")
    iam.add_user_to_group(GroupName="developers", UserName="bob")
    iam.create_login_profile(UserName="bob", Password="An0therSecret!pw", PasswordResetRequired=False)
    s3.create_bucket(Bucket="acme-logs-archive")
    s3.put_public_access_block(
        Bucket="acme-logs-archive",
        PublicAccessBlockConfiguration={k: True for k in
                                        ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")},
    )
    ec2.create_volume(AvailabilityZone=f"{REGION}b", Size=20, Encrypted=True)
