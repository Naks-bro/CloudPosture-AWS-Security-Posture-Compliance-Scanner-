"""Check -> compliance-control mappings (single source of truth).

HOW TO READ THESE MAPPINGS (see docs/MAPPINGS.md for the full methodology)

* CIS: "exact" means a recommendation in the CIS AWS Foundations Benchmark
  v3.0.0 tests the same condition. Numbers were assigned from the benchmark's
  section structure; verify against the licensed PDF for your audit. A check
  with no CIS entry is an extra hardening check that CIS v3.0.0 has no
  recommendation for.
* ISO 27001 / PCI DSS / SOC 2: AWS publishes no authoritative crosswalk from
  these CIS recommendations to those frameworks, so every entry is a THEMATIC
  mapping chosen by the maintainer based on control intent, and is marked
  "approximate". Passing a check is evidence toward the control, never proof
  of compliance with it.
"""
from __future__ import annotations

from cloudposture.models import CIS, ISO27001, PCI_DSS, SOC2, Mapping

E, A = "exact", "approximate"


def _m(ref: str, title: str, conf: str = A) -> Mapping:
    return Mapping(ref, title, conf)


# --- reusable control references -------------------------------------------
ISO_AUTH = _m("A.8.5", "Secure authentication")
ISO_AUTHINFO = _m("A.5.17", "Authentication information")
ISO_RIGHTS = _m("A.5.18", "Access rights")
ISO_ACCESSCTL = _m("A.5.15", "Access control")
ISO_PRIV = _m("A.8.2", "Privileged access rights")
ISO_INFOACCESS = _m("A.8.3", "Information access restriction")
ISO_NET = _m("A.8.20", "Networks security")
ISO_CRYPTO = _m("A.8.24", "Use of cryptography")
ISO_LOG = _m("A.8.15", "Logging")
ISO_MON = _m("A.8.16", "Monitoring activities")
ISO_CONFIG = _m("A.8.9", "Configuration management")

PCI_MFA = _m("8.4.2", "MFA for all access into the CDE")
PCI_PWLEN = _m("8.3.6", "Minimum password length")
PCI_PWREUSE = _m("8.3.7", "Password history")
PCI_PWAGE = _m("8.3.9", "Periodic password/credential change")
PCI_INACTIVE = _m("8.2.6", "Inactive accounts removed/disabled")
PCI_LEASTPRIV = _m("7.2.2", "Access based on least privilege")
PCI_ACCESSMODEL = _m("7.2.1", "Access control model defined")
PCI_NET1 = _m("1.3.1", "Inbound traffic to the CDE restricted")
PCI_NET2 = _m("1.4.2", "Inbound traffic from untrusted networks restricted")
PCI_STORE = _m("3.5.1", "Stored account data rendered unreadable")
PCI_TRANSIT = _m("4.2.1", "Strong cryptography for transmission")
PCI_LOGON = _m("10.2.1", "Audit logs enabled")
PCI_LOGINT = _m("10.3.4", "Integrity/change detection on audit logs")
PCI_LOGPROT = _m("10.3.2", "Audit log files protected from modification")
PCI_LOGREV = _m("10.4.1", "Audit logs reviewed")
PCI_CONFIG = _m("2.2.1", "Configuration standards")

SOC_LOGICAL = _m("CC6.1", "Logical access security")
SOC_REG = _m("CC6.2", "Access provisioning and removal")
SOC_ROLES = _m("CC6.3", "Role-based access / least privilege")
SOC_BOUNDARY = _m("CC6.6", "Boundary protection")
SOC_TRANSIT = _m("CC6.7", "Data transmission protection")
SOC_MON = _m("CC7.2", "Monitoring of system components")


def _cis(ref: str, title: str, conf: str = E) -> list[Mapping]:
    return [Mapping(ref, title, conf)]


MAPPINGS: dict[str, dict[str, list[Mapping]]] = {
    # ---------------------------------------------------------------- IAM
    "IAM-001": {CIS: _cis("1.5", "Ensure MFA is enabled for the root user account"),
                ISO27001: [ISO_AUTH], PCI_DSS: [PCI_MFA], SOC2: [SOC_LOGICAL]},
    "IAM-002": {CIS: _cis("1.4", "Ensure no root user account access key exists"),
                ISO27001: [ISO_PRIV], PCI_DSS: [PCI_LEASTPRIV], SOC2: [SOC_LOGICAL]},
    "IAM-003": {CIS: _cis("1.6", "Ensure hardware MFA is enabled for the root user account"),
                ISO27001: [ISO_AUTH], PCI_DSS: [PCI_MFA], SOC2: [SOC_LOGICAL]},
    "IAM-004": {CIS: _cis("1.10", "Ensure MFA is enabled for all IAM users that have a console password"),
                ISO27001: [ISO_AUTH], PCI_DSS: [PCI_MFA], SOC2: [SOC_LOGICAL]},
    "IAM-005": {CIS: _cis("1.14", "Ensure access keys are rotated every 90 days or less"),
                ISO27001: [ISO_AUTHINFO], PCI_DSS: [PCI_PWAGE], SOC2: [SOC_LOGICAL]},
    "IAM-006": {CIS: _cis("1.12", "Ensure credentials unused for 45 days or more are disabled"),
                ISO27001: [ISO_RIGHTS], PCI_DSS: [PCI_INACTIVE], SOC2: [SOC_REG]},
    "IAM-007": {CIS: _cis("1.8", "Ensure IAM password policy requires minimum length of 14 or greater"),
                ISO27001: [ISO_AUTHINFO], PCI_DSS: [PCI_PWLEN], SOC2: [SOC_LOGICAL]},
    "IAM-008": {CIS: _cis("1.9", "Ensure IAM password policy prevents password reuse"),
                ISO27001: [ISO_AUTHINFO], PCI_DSS: [PCI_PWREUSE], SOC2: [SOC_LOGICAL]},
    "IAM-009": {CIS: _cis("1.13", "Ensure there is only one active access key available for any single IAM user"),
                ISO27001: [ISO_RIGHTS], PCI_DSS: [PCI_LEASTPRIV], SOC2: [SOC_ROLES]},
    "IAM-010": {CIS: _cis("1.16", "Ensure IAM policies that allow full \"*:*\" administrative privileges are not attached"),
                ISO27001: [ISO_PRIV], PCI_DSS: [PCI_LEASTPRIV], SOC2: [SOC_ROLES]},
    "IAM-011": {CIS: _cis("1.15", "Ensure IAM users receive permissions only through groups"),
                ISO27001: [ISO_ACCESSCTL], PCI_DSS: [PCI_ACCESSMODEL], SOC2: [SOC_ROLES]},
    # ----------------------------------------------------------------- S3
    "S3-001": {CIS: _cis("2.1.4", "Ensure S3 is configured with 'Block Public Access' (account level)"),
               ISO27001: [ISO_INFOACCESS], PCI_DSS: [PCI_ACCESSMODEL, PCI_NET2],
               SOC2: [SOC_LOGICAL, SOC_BOUNDARY]},
    "S3-002": {CIS: _cis("2.1.4", "Ensure S3 is configured with 'Block Public Access' (bucket level)"),
               ISO27001: [ISO_INFOACCESS], PCI_DSS: [PCI_ACCESSMODEL, PCI_NET2],
               SOC2: [SOC_LOGICAL, SOC_BOUNDARY]},
    # No direct CIS v3.0.0 recommendation tests effective public exposure via ACL/policy.
    "S3-003": {ISO27001: [ISO_INFOACCESS], PCI_DSS: [PCI_ACCESSMODEL, PCI_NET2],
               SOC2: [SOC_LOGICAL, SOC_BOUNDARY]},
    # CIS v1.4/v1.5 required S3 encryption at rest (2.1.1); v3.0.0 dropped it because
    # S3 now encrypts all new objects by default. Kept as an extra hardening check.
    "S3-004": {ISO27001: [ISO_CRYPTO], PCI_DSS: [PCI_STORE], SOC2: [SOC_LOGICAL]},
    "S3-005": {CIS: _cis("2.1.1", "Ensure S3 Bucket Policy is set to deny HTTP requests"),
               ISO27001: [ISO_CRYPTO], PCI_DSS: [PCI_TRANSIT], SOC2: [SOC_TRANSIT]},
    # ---------------------------------------------------------------- EC2
    "EC2-001": {CIS: [Mapping("5.2", "No security groups allow ingress from 0.0.0.0/0 to remote server administration ports", E),
                      Mapping("5.3", "No security groups allow ingress from ::/0 to remote server administration ports", E)],
                ISO27001: [ISO_NET], PCI_DSS: [PCI_NET1, PCI_NET2], SOC2: [SOC_BOUNDARY]},
    "EC2-002": {CIS: [Mapping("5.2", "No security groups allow ingress from 0.0.0.0/0 to remote server administration ports", E),
                      Mapping("5.3", "No security groups allow ingress from ::/0 to remote server administration ports", E)],
                ISO27001: [ISO_NET], PCI_DSS: [PCI_NET1, PCI_NET2], SOC2: [SOC_BOUNDARY]},
    "EC2-003": {CIS: _cis("5.4", "Ensure the default security group of every VPC restricts all traffic"),
                ISO27001: [ISO_NET], PCI_DSS: [PCI_NET1, PCI_NET2], SOC2: [SOC_BOUNDARY]},
    "EC2-004": {CIS: _cis("2.2.1", "Ensure EBS Volume Encryption is Enabled in all Regions"),
                ISO27001: [ISO_CRYPTO], PCI_DSS: [PCI_STORE], SOC2: [SOC_LOGICAL]},
    "EC2-005": {CIS: _cis("2.2.1", "Ensure EBS Volume Encryption is Enabled in all Regions (volume-level evidence)", A),
                ISO27001: [ISO_CRYPTO], PCI_DSS: [PCI_STORE], SOC2: [SOC_LOGICAL]},
    "EC2-006": {CIS: _cis("5.6", "Ensure that EC2 Metadata Service only allows IMDSv2"),
                ISO27001: [ISO_CONFIG], PCI_DSS: [PCI_CONFIG], SOC2: [SOC_LOGICAL]},
    # --------------------------------------------------------- CloudTrail
    "CT-001": {CIS: _cis("3.1", "Ensure CloudTrail is enabled in all regions"),
               ISO27001: [ISO_LOG], PCI_DSS: [PCI_LOGON], SOC2: [SOC_MON]},
    "CT-002": {CIS: _cis("3.2", "Ensure CloudTrail log file validation is enabled"),
               ISO27001: [ISO_LOG], PCI_DSS: [PCI_LOGINT], SOC2: [SOC_MON]},
    "CT-003": {CIS: _cis("3.4", "Ensure CloudTrail trails are integrated with CloudWatch Logs"),
               ISO27001: [ISO_MON], PCI_DSS: [PCI_LOGREV], SOC2: [SOC_MON]},
    "CT-004": {CIS: _cis("3.7", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"),
               ISO27001: [ISO_CRYPTO], PCI_DSS: [PCI_LOGPROT], SOC2: [SOC_LOGICAL]},
}
