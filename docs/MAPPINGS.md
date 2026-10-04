# Compliance mapping methodology

Compliance mappings are easy to over-claim, so this project is explicit about how each one was made.
The mappings live in one file: [`src/cloudposture/compliance/mappings.py`](../src/cloudposture/compliance/mappings.py).
The per-check table is generated in [CHECKS.md](CHECKS.md).

## Confidence levels

| Level | Meaning |
|-------|---------|
| `exact` | A recommendation in the framework tests the same condition as the check. |
| `approximate` | The check is thematically related to the control (same security intent) but is not what the control literally requires. |

## Per framework

### CIS AWS Foundations Benchmark v3.0.0 - mostly `exact`
Each check was written to mirror the *audit* of a specific CIS recommendation (e.g. IAM-001 = 1.5, EC2-003 = 5.4,
CT-002 = 3.2). Exceptions:

* **EC2-005** (per-volume encryption) is mapped to 2.2.1 as `approximate`: 2.2.1 is about the regional *default*
  setting; volume-level results are supporting evidence.
* **S3-003** (public via ACL/policy) and **S3-004** (default encryption) have **no CIS v3.0.0 mapping**. They are
  extra hardening checks. (Earlier CIS versions, 1.4/1.5, did require S3 encryption at rest; v3.0.0 does not,
  because S3 now encrypts all new objects by default.)
* CIS controls that need manual/organisational evidence, or services not scanned (RDS, VPC flow logs, CloudWatch
  metric-filter alarms, AWS Config) are **not implemented** - they are not silently reported as passing.

Recommendation numbers differ between benchmark versions (e.g. S3 deny-HTTP is 2.1.2 in v1.4 and 2.1.1 in v3.0.0).
The numbers here were assigned from the v3.0.0 section structure; **verify them against the licensed CIS PDF
before using them as audit evidence.** The CIS Benchmarks are © Center for Internet Security; this repository
reproduces only control numbers and short titles.

### ISO/IEC 27001:2022 Annex A, PCI DSS v4.0, SOC 2 (2017 TSC) - always `approximate`
There is no authoritative AWS-published crosswalk from these CIS recommendations to these frameworks.
Mappings were chosen by the maintainer from the **intent** of each control, for example:

| Theme | ISO 27001 | PCI DSS | SOC 2 |
|-------|-----------|---------|-------|
| MFA | A.8.5 Secure authentication | 8.4.2 | CC6.1 |
| Passwords | A.5.17 Authentication information | 8.3.6 / 8.3.7 | CC6.1 |
| Dormant/rotated credentials | A.5.18 Access rights / A.5.17 | 8.2.6 / 8.3.9 | CC6.2 / CC6.1 |
| Least privilege | A.8.2 Privileged access / A.5.15 | 7.2.1 / 7.2.2 | CC6.3 |
| Public exposure & network | A.8.3 / A.8.20 | 1.3.1 / 1.4.2 / 7.2.1 | CC6.1 / CC6.6 |
| Encryption | A.8.24 Cryptography | 3.5.1 / 4.2.1 | CC6.1 / CC6.7 |
| Logging | A.8.15 Logging / A.8.16 | 10.2.1 / 10.3.x / 10.4.1 | CC7.2 |

Caveats:

* A single AWS setting rarely satisfies a whole PCI/ISO/SOC 2 requirement; these frameworks also need process and
  evidence that a configuration scanner cannot see. A passing check is *evidence toward* a control, never proof.
* PCI DSS requirements apply to the cardholder-data environment (CDE) only. The scanner does not know your scope.
* SOC 2 criteria are outcome-based and auditor-interpreted; the CC references are indicative only.
* A test (`tests/test_registry.py`) fails the build if any non-CIS mapping is marked `exact`.

### How framework scores are computed
A framework's pass rate is `passed / (passed + failed)` over the resource-level findings whose check maps to at
least one control of that framework. The dashboard also shows how many checks are mapped, so a high score on a
small mapped subset is visible as such.

If you spot a mapping you disagree with, edit `mappings.py`, run `python scripts/generate_docs.py` and open a PR.
