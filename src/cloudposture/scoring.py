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
        severity=severity, service=dict(service), frameworks=frameworks,
    )
