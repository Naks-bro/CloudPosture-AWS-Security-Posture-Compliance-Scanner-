"""Scoring and aggregation.

Definitions (also documented in README):
* Only PASS and FAIL findings are *scored*. ERROR (could not evaluate) and N/A
  (nothing to evaluate) are reported separately and never inflate the score.
* pass_rate           = PASS / (PASS + FAIL) over resource-level findings.
* check_pass_rate     = share of checks whose every scored finding passed.
* weighted_score      = severity-weighted pass rate (CRITICAL 10, HIGH 6, MEDIUM 3, LOW 1).
* framework pass rate = pass rate over findings whose check maps to that framework.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from cloudposture.models import FRAMEWORKS, SEVERITY_ORDER, Finding, Status


def _rate(passed: int, failed: int) -> float | None:
    total = passed + failed
    return round(100 * passed / total, 1) if total else None


@dataclass
class Bucket:
    passed: int = 0
    failed: int = 0

    @property
    def total(self) -> int:
        return self.passed + self.failed

    @property
    def pass_rate(self) -> float | None:
        return _rate(self.passed, self.failed)

    def add(self, f: Finding) -> None:
        if f.status is Status.PASS:
            self.passed += 1
        elif f.status is Status.FAIL:
            self.failed += 1


@dataclass
class FrameworkSummary:
    framework: str
    name: str
    bucket: Bucket
    checks_mapped: int
    checks_total: int
    controls: dict[str, Bucket]

    @property
    def coverage_pct(self) -> float:
        return round(100 * self.checks_mapped / self.checks_total, 1) if self.checks_total else 0.0


@dataclass
class Summary:
    total_findings: int
    scored: int
    passed: int
    failed: int
    errors: int
    not_applicable: int
    pass_rate: float | None
    weighted_score: float | None
    checks_total: int
    checks_passed: int
    check_pass_rate: float | None
    severity: dict[str, Bucket] = field(default_factory=dict)
    service: dict[str, Bucket] = field(default_factory=dict)
    frameworks: dict[str, FrameworkSummary] = field(default_factory=dict)
    checks_executed: int = 0  # distinct checks that produced any finding (incl. ERROR / N/A)


def summarize(findings: list[Finding]) -> Summary:
    overall = Bucket()
    severity = {s: Bucket() for s in SEVERITY_ORDER}
    service: dict[str, Bucket] = defaultdict(Bucket)
    per_check: dict[str, list[Finding]] = defaultdict(list)
    w_pass = w_total = 0
    errors = na = 0

    for f in findings:
        if f.status is Status.ERROR:
            errors += 1
        elif f.status is Status.NOT_APPLICABLE:
            na += 1
        else:
            overall.add(f)
            severity[f.severity.value].add(f)
            service[f.service].add(f)
            per_check[f.check_id].append(f)
            w_total += f.severity.weight
            w_pass += f.severity.weight if f.status is Status.PASS else 0

    checks_passed = sum(all(x.status is Status.PASS for x in fs) for fs in per_check.values())
    all_check_ids = {f.check_id for f in findings}

    frameworks: dict[str, FrameworkSummary] = {}
    for fw, fw_name in FRAMEWORKS.items():
        bucket, controls = Bucket(), defaultdict(Bucket)
        mapped_checks = {f.check_id for f in findings if f.mapped_to(fw)}
        for f in findings:
            if not f.mapped_to(fw) or f.status not in (Status.PASS, Status.FAIL):
                continue
            bucket.add(f)
            for m in f.mappings[fw]:
                controls[m.control_id].add(f)
        frameworks[fw] = FrameworkSummary(fw, fw_name, bucket, len(mapped_checks), len(all_check_ids), dict(controls))

    return Summary(
        total_findings=len(findings), scored=overall.total, passed=overall.passed, failed=overall.failed,
        errors=errors, not_applicable=na, pass_rate=overall.pass_rate,
        weighted_score=round(100 * w_pass / w_total, 1) if w_total else None,
        checks_total=len(per_check), checks_passed=checks_passed,
        check_pass_rate=_rate(checks_passed, len(per_check) - checks_passed),
        severity=severity, service=dict(service), frameworks=frameworks, checks_executed=len(all_check_ids),
    )


# ---------------------------------------------------------------------------
# Additional read-models used by the dashboard (pure functions over findings)
# ---------------------------------------------------------------------------
SERVICE_ORDER = ["IAM", "S3", "EC2", "CloudTrail"]


def posture_grade(summary: Summary) -> str:
    """Qualitative rating shown next to the score.

    Poor             - any CRITICAL failure, or pass rate < 60%
    Needs attention  - pass rate < 85% or any HIGH failure
    Healthy          - otherwise
    Not scored       - nothing was evaluated
    """
    if summary.pass_rate is None:
        return "Not scored"
    if summary.severity["CRITICAL"].failed > 0 or summary.pass_rate < 60:
        return "Poor"
    if summary.pass_rate < 85 or summary.severity["HIGH"].failed > 0:
        return "Needs attention"
    return "Healthy"


@dataclass
class ServiceStats:
    service: str
    checks: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    not_applicable: int = 0
    failed_by_severity: dict[str, int] = field(default_factory=lambda: {s: 0 for s in SEVERITY_ORDER})

    @property
    def pass_rate(self) -> float | None:
        return _rate(self.passed, self.failed)


def service_breakdown(findings: list[Finding]) -> dict[str, ServiceStats]:
    """Per-service counts of every status (errors and N/A included) and failed-by-severity."""
    stats: dict[str, ServiceStats] = {}
    checks: dict[str, set[str]] = defaultdict(set)
    for f in findings:
        s = stats.setdefault(f.service, ServiceStats(f.service))
        checks[f.service].add(f.check_id)
        if f.status is Status.PASS:
            s.passed += 1
        elif f.status is Status.FAIL:
            s.failed += 1
            s.failed_by_severity[f.severity.value] += 1
        elif f.status is Status.ERROR:
            s.errors += 1
        else:
            s.not_applicable += 1
    for name, ids in checks.items():
        stats[name].checks = len(ids)
    order = {n: i for i, n in enumerate(SERVICE_ORDER)}
    return dict(sorted(stats.items(), key=lambda kv: (order.get(kv[0], 99), kv[0])))


def check_statuses(findings: list[Finding]) -> dict[str, Status]:
    """One status per check: FAIL > ERROR > PASS > N/A."""
    precedence = {Status.FAIL: 3, Status.ERROR: 2, Status.PASS: 1, Status.NOT_APPLICABLE: 0}
    out: dict[str, Status] = {}
    for f in findings:
        if f.check_id not in out or precedence[f.status] > precedence[out[f.check_id]]:
            out[f.check_id] = f.status
    return out


@dataclass
class ControlRow:
    control_id: str
    title: str
    confidence: str  # "exact" | "approximate" (approximate wins if mixed)
    passed: int = 0
    failed: int = 0
    checks: list[str] = field(default_factory=list)

    @property
    def pass_rate(self) -> float | None:
        return _rate(self.passed, self.failed)


def control_rows(findings: list[Finding], framework: str) -> list[ControlRow]:
    """Per-control results for one framework (only PASS/FAIL findings are scored)."""
    rows: dict[str, ControlRow] = {}
    for f in findings:
        for m in f.mappings.get(framework, []):
            r = rows.setdefault(m.control_id, ControlRow(m.control_id, m.title, m.confidence))
            if m.confidence == "approximate":
                r.confidence = "approximate"
            if f.check_id not in r.checks:
                r.checks.append(f.check_id)
            if f.status is Status.PASS:
                r.passed += 1
            elif f.status is Status.FAIL:
                r.failed += 1
    return sorted(rows.values(), key=lambda r: [(0, int(p), "") if p.isdigit() else (1, 0, p) for p in r.control_id.split(".")])
