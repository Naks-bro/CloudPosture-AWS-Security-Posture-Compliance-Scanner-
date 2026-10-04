from cloudposture.checks import REGISTRY
from cloudposture.compliance.mappings import MAPPINGS
from cloudposture.models import CIS, FRAMEWORKS


def test_check_count_and_services():
    assert len(REGISTRY) >= 24
    assert {rc.spec.service for rc in REGISTRY.values()} == {"IAM", "S3", "EC2", "CloudTrail"}


def test_every_check_has_mapping_entry_and_no_orphans():
    assert set(MAPPINGS) == set(REGISTRY)


def test_mappings_are_wellformed():
    for cid, fws in MAPPINGS.items():
        assert set(fws) <= set(FRAMEWORKS), cid
        for fw, ms in fws.items():
            assert ms, f"{cid}/{fw} empty"
            for m in ms:
                assert m.confidence in {"exact", "approximate"}
                assert m.control_id and m.title


def test_non_cis_mappings_are_never_claimed_exact():
    """No authoritative crosswalk exists for ISO/PCI/SOC2, so they must stay 'approximate'."""
    for cid, fws in MAPPINGS.items():
        for fw, ms in fws.items():
            if fw != CIS:
                assert all(m.confidence == "approximate" for m in ms), (cid, fw)


def test_every_check_has_remediation_and_expected_state():
    for rc in REGISTRY.values():
        assert rc.spec.remediation and rc.spec.expected and rc.spec.description


def test_docs_checks_md_is_up_to_date():
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    r = subprocess.run([sys.executable, str(root / "scripts" / "generate_docs.py"), "--check"])
    assert r.returncode == 0, "docs/CHECKS.md is stale: run `python scripts/generate_docs.py`"


def test_iam_policy_document_is_read_only():
    import json
    from pathlib import Path

    doc = json.loads((Path(__file__).resolve().parents[1] / "docs" / "iam-policy.json").read_text())
    actions = [a for st in doc["Statement"] for a in st["Action"]]
    assert all(st["Effect"] == "Allow" for st in doc["Statement"])
    for a in actions:
        verb = a.split(":")[1]
        assert verb.startswith(("Get", "List", "Describe")) or a == "iam:GenerateCredentialReport", a
