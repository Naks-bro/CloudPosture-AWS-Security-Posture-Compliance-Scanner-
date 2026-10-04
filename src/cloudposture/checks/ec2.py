"""EC2/VPC/EBS checks, evaluated in every in-scope region."""
from __future__ import annotations

from typing import Any

from cloudposture.checks.base import FindingFactory, ScanContext, check, per_region
from cloudposture.models import Finding, Severity

SVC = "EC2"
OPEN_V4, OPEN_V6 = "0.0.0.0/0", "::/0"


def _security_groups(ctx: ScanContext, region: str) -> list[dict[str, Any]]:
    def fetch() -> list[dict[str, Any]]:
        pages = ctx.client("ec2", region).get_paginator("describe_security_groups").paginate()
        return [sg for p in pages for sg in p["SecurityGroups"]]

    return ctx.memo(f"sgs:{region}", fetch)


def exposed_sources(sg: dict[str, Any], port: int) -> list[str]:
    """World-open CIDRs (v4/v6) on inbound rules that cover ``port``."""
    found: set[str] = set()
    for perm in sg.get("IpPermissions", []):
        proto = perm.get("IpProtocol")
        if proto == "-1":
            covers = True  # all protocols / all ports
        elif proto in ("tcp", "6"):
            covers = perm.get("FromPort", 0) <= port <= perm.get("ToPort", 65535)
        else:
            covers = False
        if not covers:
            continue
        found.update(r["CidrIp"] for r in perm.get("IpRanges", []) if r.get("CidrIp") == OPEN_V4)
        found.update(r["CidrIpv6"] for r in perm.get("Ipv6Ranges", []) if r.get("CidrIpv6") == OPEN_V6)
    return sorted(found)


def _admin_port_check(ctx: ScanContext, f: FindingFactory, port: int, label: str) -> list[Finding]:
    def run(region: str) -> list[Finding]:
        out = []
        for sg in _security_groups(ctx, region):
            exposed = exposed_sources(sg, port)
            res = f"{sg['GroupId']} ({sg.get('GroupName', '')})"
            state = f"{label} open to {', '.join(exposed)}" if exposed else f"{label} not open to the internet"
            out.append(f.evaluate(not exposed, res, state, region))
        return out

    return per_region(ctx, f, run)


@check(
    id="EC2-001", service=SVC, severity=Severity.HIGH,
    title="Security group does not expose SSH (22) to the internet",
    description="SSH open to 0.0.0.0/0 or ::/0 (including all-port/all-protocol rules) invites brute-force and exploit attempts.",
    expected="No inbound rule allowing 0.0.0.0/0 or ::/0 on TCP 22",
    remediation=[
        "Edit the security group inbound rules; remove the world-open SSH rule or restrict it to a trusted CIDR/VPN.",
        "Prefer AWS Systems Manager Session Manager or EC2 Instance Connect Endpoint so no inbound port is required.",
    ],
)
def sg_ssh(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    return _admin_port_check(ctx, f, 22, "SSH (22)")


@check(
    id="EC2-002", service=SVC, severity=Severity.HIGH,
    title="Security group does not expose RDP (3389) to the internet",
    description="RDP open to the internet is a leading ransomware entry point.",
    expected="No inbound rule allowing 0.0.0.0/0 or ::/0 on TCP 3389",
    remediation=[
        "Remove the world-open RDP rule or restrict to a trusted CIDR/VPN.",
        "Use Systems Manager Fleet Manager / Session Manager port forwarding or a bastion behind a VPN.",
    ],
)
def sg_rdp(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    return _admin_port_check(ctx, f, 3389, "RDP (3389)")


@check(
    id="EC2-003", service=SVC, severity=Severity.MEDIUM,
    title="Default security group restricts all traffic",
    description="Resources launched without an explicit group fall into the default SG; it should allow nothing.",
    expected="Default security group has no inbound and no outbound rules",
    remediation=[
        "Remove all inbound and outbound rules from the default security group of each VPC.",
        "Create purpose-specific security groups and attach those to resources.",
    ],
)
def default_sg(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(region: str) -> list[Finding]:
        out = []
        for sg in _security_groups(ctx, region):
            if sg.get("GroupName") != "default":
                continue
            n_in, n_out = len(sg.get("IpPermissions", [])), len(sg.get("IpPermissionsEgress", []))
            out.append(f.evaluate(n_in == 0 and n_out == 0, f"{sg['GroupId']} ({sg.get('VpcId', 'no-vpc')})",
                                  f"{n_in} inbound and {n_out} outbound rule(s)", region))
        return out

    return per_region(ctx, f, run)


@check(
    id="EC2-004", service=SVC, severity=Severity.MEDIUM,
    title="EBS encryption by default is enabled in the region",
    description="With the account-level default on, every new EBS volume and snapshot copy is encrypted automatically.",
    expected="EBS encryption by default is enabled in every region",
    remediation=["EC2 > Settings > Data protection and security > EBS encryption > Manage > Enable (repeat per region)."],
)
def ebs_default_encryption(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(region: str) -> list[Finding]:
        on = ctx.client("ec2", region).get_ebs_encryption_by_default()["EbsEncryptionByDefault"]
        return [f.evaluate(on, f"ebs-default-encryption/{region}", "Enabled" if on else "Disabled", region)]

    return per_region(ctx, f, run)


@check(
    id="EC2-005", service=SVC, severity=Severity.MEDIUM,
    title="EBS volume is encrypted",
    description="Unencrypted volumes expose data if snapshots are shared or the underlying media is mishandled.",
    expected="Volume Encrypted = true",
    remediation=[
        "Snapshot the volume, copy the snapshot with encryption enabled, and create a new volume from it.",
        "Swap the volume on the instance during a maintenance window, then delete the unencrypted volume/snapshots.",
    ],
)
def ebs_volumes_encrypted(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(region: str) -> list[Finding]:
        pages = ctx.client("ec2", region).get_paginator("describe_volumes").paginate()
        return [
            f.evaluate(v["Encrypted"], v["VolumeId"], "Encrypted" if v["Encrypted"] else "NOT encrypted", region)
            for p in pages for v in p["Volumes"]
        ]

    out = per_region(ctx, f, run)
    return out or [f.not_applicable("account", "No EBS volumes in scanned regions")]


@check(
    id="EC2-006", service=SVC, severity=Severity.MEDIUM,
    title="Instance requires IMDSv2",
    description="IMDSv1 is vulnerable to SSRF-based credential theft (e.g. the 2019 Capital One breach pattern).",
    expected="Instance metadata option HttpTokens = required",
    remediation=[
        "EC2 > instance > Actions > Instance settings > Modify instance metadata options > IMDSv2 'Required'.",
        "Set the account/region default for new instances to IMDSv2 required.",
    ],
)
def imdsv2(ctx: ScanContext, f: FindingFactory) -> list[Finding]:
    def run(region: str) -> list[Finding]:
        out = []
        for page in ctx.client("ec2", region).get_paginator("describe_instances").paginate():
            for r in page["Reservations"]:
                for i in r["Instances"]:
                    if i["State"]["Name"] in ("terminated", "shutting-down"):
                        continue
                    tokens = i.get("MetadataOptions", {}).get("HttpTokens", "optional")
                    out.append(f.evaluate(tokens == "required", i["InstanceId"], f"HttpTokens = {tokens}", region))
        return out

    out = per_region(ctx, f, run)
    return out or [f.not_applicable("account", "No EC2 instances in scanned regions")]
