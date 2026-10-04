from cloudposture.models import CIS, ISO27001, Finding, Mapping, Severity, Status
from cloudposture.scoring import summarize


def F(cid, status, sev=Severity.HIGH, svc="IAM", maps=None):
    return Finding(cid, svc, "r", "global", sev, "t", "d", "c", "e", status, ["fix"], maps or {})


def test_empty():
    s = summarize([])
    assert s.pass_rate is None and s.weighted_score is None and s.scored == 0


def test_error_and_na_do_not_count():
    s = summarize([F("A", Status.PASS), F("B", Status.FAIL), F("C", Status.ERROR), F("D", Status.NOT_APPLICABLE)])
    assert (s.passed, s.failed, s.errors, s.not_applicable) == (1, 1, 1, 1)
    assert s.pass_rate == 50.0


def test_all_error_has_no_score():
    assert summarize([F("A", Status.ERROR)]).pass_rate is None


def test_severity_and_service_breakdown():
    s = summarize([
        F("A", Status.FAIL, Severity.CRITICAL, "S3"), F("B", Status.PASS, Severity.CRITICAL, "S3"),
        F("C", Status.FAIL, Severity.LOW, "EC2"),
    ])
    assert s.severity["CRITICAL"].failed == 1 and s.severity["CRITICAL"].passed == 1
    assert s.severity["LOW"].failed == 1
    assert s.service["S3"].pass_rate == 50.0 and s.service["EC2"].pass_rate == 0.0


def test_weighted_score():
    # CRITICAL(10) passes, LOW(1) fails -> 10/11
    s = summarize([F("A", Status.PASS, Severity.CRITICAL), F("B", Status.FAIL, Severity.LOW)])
    assert s.weighted_score == round(100 * 10 / 11, 1)


def test_check_level_rate_requires_all_resources_to_pass():
    s = summarize([F("A", Status.PASS), F("A", Status.FAIL), F("B", Status.PASS)])
    assert (s.checks_total, s.checks_passed, s.check_pass_rate) == (2, 1, 50.0)


def test_framework_rates_use_only_mapped_findings():
    m = Mapping("1.5", "x", "exact")
    s = summarize([
        F("A", Status.PASS, maps={CIS: [m]}), F("B", Status.FAIL, maps={CIS: [m]}),
        F("C", Status.FAIL, maps={ISO27001: [Mapping("A.8.5", "x")]}), F("D", Status.FAIL),
    ])
    cis = s.frameworks[CIS]
    assert cis.bucket.pass_rate == 50.0 and cis.checks_mapped == 2 and cis.checks_total == 4
    assert cis.controls["1.5"].total == 2
    assert s.frameworks[ISO27001].bucket.pass_rate == 0.0
