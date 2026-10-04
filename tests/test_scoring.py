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


# ---- dashboard read-models -------------------------------------------------
from cloudposture.scoring import check_statuses, control_rows, posture_grade, service_breakdown  # noqa: E402


def test_posture_grade_rules():
    def g(findings):
        return posture_grade(summarize(findings))

    assert g([]) == "Not scored"
    assert g([F("A", Status.PASS)] * 10) == "Healthy"
    assert g([F("A", Status.PASS)] * 9 + [F("B", Status.FAIL, Severity.LOW)]) == "Healthy"          # 90%
    assert g([F("A", Status.PASS)] * 9 + [F("B", Status.FAIL, Severity.HIGH)]) == "Needs attention"  # high failure
    assert g([F("A", Status.PASS)] * 7 + [F("B", Status.FAIL, Severity.LOW)] * 3) == "Needs attention"  # 70%
    assert g([F("A", Status.PASS)] * 99 + [F("B", Status.FAIL, Severity.CRITICAL)]) == "Poor"        # any critical
    assert g([F("A", Status.PASS)] * 5 + [F("B", Status.FAIL, Severity.LOW)] * 5) == "Poor"          # 50%


def test_service_breakdown_counts_all_statuses():
    fs = [F("A", Status.PASS, svc="S3"), F("A", Status.FAIL, Severity.HIGH, "S3"), F("B", Status.ERROR, svc="S3"),
          F("C", Status.NOT_APPLICABLE, svc="IAM"), F("D", Status.FAIL, Severity.CRITICAL, "IAM")]
    b = service_breakdown(fs)
    assert list(b) == ["IAM", "S3"]  # fixed display order
    s3 = b["S3"]
    assert (s3.checks, s3.passed, s3.failed, s3.errors) == (2, 1, 1, 1)
    assert s3.failed_by_severity["HIGH"] == 1 and s3.pass_rate == 50.0
    assert b["IAM"].not_applicable == 1 and b["IAM"].failed_by_severity["CRITICAL"] == 1


def test_check_status_precedence():
    fs = [F("A", Status.PASS), F("A", Status.FAIL), F("B", Status.ERROR), F("B", Status.PASS),
          F("C", Status.NOT_APPLICABLE), F("D", Status.PASS)]
    assert check_statuses(fs) == {"A": Status.FAIL, "B": Status.ERROR, "C": Status.NOT_APPLICABLE, "D": Status.PASS}


def test_control_rows_confidence_and_order():
    fs = [
        F("A", Status.PASS, maps={CIS: [Mapping("1.10", "t", "exact")]}),
        F("B", Status.FAIL, maps={CIS: [Mapping("1.5", "t", "exact"), Mapping("1.10", "t", "approximate")]}),
        F("C", Status.ERROR, maps={CIS: [Mapping("1.5", "t", "exact")]}),
    ]
    rows = control_rows(fs, CIS)
    assert [r.control_id for r in rows] == ["1.5", "1.10"]  # numeric, not lexical
    r15, r110 = rows
    assert (r15.passed, r15.failed, r15.confidence, r15.checks) == (0, 1, "exact", ["B", "C"])
    assert (r110.passed, r110.failed, r110.confidence) == (1, 1, "approximate")


def test_checks_executed_counts_errors_and_na_too():
    s = summarize([F("A", Status.PASS), F("B", Status.ERROR), F("C", Status.NOT_APPLICABLE), F("A", Status.FAIL)])
    assert s.checks_executed == 3 and s.checks_total == 1  # only A was scored
