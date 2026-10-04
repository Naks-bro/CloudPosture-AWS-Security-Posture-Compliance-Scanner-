import csv
import io

from cloudposture.models import CIS, Finding, Mapping, ScanResult, Severity, Status
from cloudposture.reporting import CSV_COLUMNS, findings_to_csv, load_json, write_json


def make(resource="r1", **kw):
    base = dict(check_id="IAM-001", service="IAM", resource=resource, region="global", severity=Severity.CRITICAL,
                title="T", description="D", current_state="c", expected_state="e", status=Status.FAIL,
                remediation=["step one", "step two"], mappings={CIS: [Mapping("1.5", "x", "exact")]})
    base.update(kw)
    return Finding(**base)


def test_csv_columns_and_content():
    rows = list(csv.DictReader(io.StringIO(findings_to_csv([make()]))))
    assert list(rows[0]) == CSV_COLUMNS
    assert rows[0]["cis_mapping"] == "1.5 (exact)"
    assert rows[0]["remediation"] == "1. step one | 2. step two"
    assert rows[0]["iso27001_mapping"] == ""


def test_csv_formula_injection_neutralised():
    rows = list(csv.DictReader(io.StringIO(findings_to_csv([make(resource="=HYPERLINK(\"http://x\")")]))))
    assert rows[0]["resource"].startswith("'=")


def test_json_roundtrip(tmp_path):
    original = ScanResult([make()])
    p = write_json(original, tmp_path / "x.json")
    loaded = load_json(p)
    assert loaded.findings[0].to_dict() == original.findings[0].to_dict()
