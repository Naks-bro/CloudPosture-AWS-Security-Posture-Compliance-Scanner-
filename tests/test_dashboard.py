from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from cloudposture.checks import REGISTRY
from cloudposture.models import CIS, ISO27001, Finding, Mapping, ScanMetadata, Severity, Status
from cloudposture.reporting import load_json
from cloudposture.scoring import check_statuses, summarize
from dashboard import components as c
from dashboard.data import apply_filters, catalog_frame, findings_frame, sort_findings

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "sample_data" / "sample_scan.json"
APP = str(ROOT / "dashboard" / "app.py")


@pytest.fixture(scope="module")
def findings():
    return load_json(SAMPLE).findings


def mk(resource="r", status=Status.FAIL, **kw):
    base = dict(check_id="X-1", service="IAM", resource=resource, region="global", severity=Severity.HIGH, title="T",
                description="D", current_state="c", expected_state="e", status=status, remediation=["do it"],
                mappings={ISO27001: [Mapping("A.8.5", "Secure authentication", "approximate")]})
    base.update(kw)
    return Finding(**base)


# ---------------------------------------------------------------- app smoke tests
def test_demo_mode_renders_all_tabs_without_exception():
    at = AppTest.from_file(APP, default_timeout=90).run()
    assert not at.exception, at.exception
    assert len(at.tabs) == 6
    assert [t.label for t in at.tabs] == ["Overview", "Findings", "Compliance", "Services", "Check catalog", "Reports"]


def test_live_mode_without_scan_shows_instructions_not_crash():
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.session_state["source"] = "Live AWS"
    at.run()
    assert not at.exception, at.exception
    assert any("Run security scan" in i.value for i in at.info)


# ---------------------------------------------------------------- data helpers
def test_filters_combine(findings):
    all_svc = {f.service for f in findings}
    out = apply_filters(findings, all_svc, {"CRITICAL"}, {"FAIL"})
    assert out and all(f.severity.value == "CRITICAL" and f.status.value == "FAIL" for f in out)
    assert {f.check_id for f in apply_filters(findings, None, None, None, check_ids={"S3-002"})} == {"S3-002"}
    assert all(f.mapped_to(CIS) for f in apply_filters(findings, None, None, None, framework=CIS))
    assert not any(f.check_id in {"S3-003", "S3-004"} for f in apply_filters(findings, None, None, None, framework=CIS))
    assert apply_filters(findings, None, None, None, text="ACME-PUBLIC")
    assert apply_filters(findings, None, None, None) == findings  # None = unrestricted


def test_sort_puts_failures_and_critical_first(findings):
    s = sort_findings(findings)
    assert s[0].status is Status.FAIL and s[0].severity is Severity.CRITICAL
    first_pass = next(i for i, f in enumerate(s) if f.status is Status.PASS)
    assert all(f.status is Status.FAIL for f in s[:first_pass])


def test_findings_frame_row_order_matches_input(findings):
    shown = sort_findings(findings)[:10]
    df = findings_frame(shown)
    assert list(df["Check"]) == [f.check_id for f in shown]  # selected row index -> shown[i]


def test_catalog_lists_every_registered_check_with_not_run(findings):
    specs = sorted((rc.spec for rc in REGISTRY.values()), key=lambda s: s.id)
    subset = [f for f in findings if f.service == "S3"]
    df = catalog_frame(specs, check_statuses(subset), {})
    assert len(df) == len(REGISTRY) >= 26
    assert set(df[df["Service"] != "S3"]["Status"]) == {"NOT RUN"}
    assert "NOT RUN" not in set(df[df["Service"] == "S3"]["Status"])


# ---------------------------------------------------------------- components
def test_region_label_is_compact():
    assert c.region_label([]) == "global / n/a"
    assert c.region_label(["us-east-1", "eu-west-1"]) == "us-east-1, eu-west-1"
    long = [f"r-{i}" for i in range(29)]
    assert c.region_label(long).startswith("29 regions") and len(c.region_label(long)) < 60


def test_dynamic_text_is_html_escaped():
    f = mk(resource='<img src=x onerror=alert(1)>', current_state='a "*:*" <b>x</b>')
    html = c.finding_detail(f) + c.priority_findings([f])
    assert "<img" not in html and "<b>x</b>" not in html
    assert "&lt;img" in html and "&quot;*:*&quot;" in html


def test_approximate_mappings_are_labelled_and_never_called_exact():
    html = c.finding_detail(mk())
    assert c.APPROX_LABEL in html and ">Exact<" not in html
    exact = mk(mappings={CIS: [Mapping("1.5", "MFA", "exact")]})
    assert ">Exact<" in c.finding_detail(exact)


def test_compliance_cards_label_mapping_confidence(findings):
    fws = summarize(findings).frameworks
    for key in ("ISO27001", "PCI_DSS", "SOC2"):
        card = c.framework_card(findings, fws[key])
        assert c.APPROX_LABEL in card and "Exact" not in card, key
    cis = c.framework_card(findings, fws["CIS"])
    assert "Mostly exact" in cis and "1 approximate" in cis  # EC2-005 is the one approximate CIS mapping
    assert c.APPROX_LABEL in c.COMPLIANCE_NOTICE and "not</b> audit or certification" in c.COMPLIANCE_NOTICE


def test_header_marks_demo_vs_live(findings):
    s = summarize(findings)
    demo = c.header(ScanMetadata(mode="demo", account_id="123", regions=["us-east-1"]), s)
    live = c.header(ScanMetadata(mode="live", account_id="123", regions=["us-east-1"]), s)
    assert "DEMO DATA" in demo and "fictional" in demo and "LIVE AWS" not in demo
    assert "LIVE AWS" in live and "DEMO DATA" not in live and "fictional" not in live
    assert "READ-ONLY" in demo and "READ-ONLY" in live


def test_hero_shows_all_four_statuses(findings):
    html = c.hero(summarize(findings))
    for label in (">PASS<", ">FAIL<", ">ERROR<", ">N/A<"):
        assert label in html
