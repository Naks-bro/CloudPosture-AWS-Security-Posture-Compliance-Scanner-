from pathlib import Path

from streamlit.testing.v1 import AppTest

from dashboard.data import apply_filters, remediation_groups, to_frame
from cloudposture.reporting import load_json

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "sample_data" / "sample_scan.json"


def test_demo_mode_renders_without_exception():
    at = AppTest.from_file(str(ROOT / "dashboard" / "app.py"), default_timeout=60).run()
    assert not at.exception, at.exception
    assert any("DEMO DATA" in m.value for m in at.markdown)


def test_filters_and_groups():
    findings = load_json(SAMPLE).findings
    sev = ["CRITICAL"]
    out = apply_filters(findings, {f.service for f in findings}, sev, {"FAIL"}, "")
    assert out and all(f.severity.value == "CRITICAL" and f.status.value == "FAIL" for f in out)
    assert apply_filters(findings, {"S3"}, ["CRITICAL", "HIGH", "MEDIUM", "LOW"], {"FAIL", "PASS"}, "acme-public")
    groups = remediation_groups(findings)
    assert groups[0][0].severity.value == "CRITICAL"
    assert len(to_frame(findings)) == len(findings)
