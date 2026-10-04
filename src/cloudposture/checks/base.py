"""Check registry, spec metadata and the scan context shared by all checks."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from botocore.exceptions import ClientError

from cloudposture.aws.session import AwsClients
from cloudposture.compliance.mappings import MAPPINGS
from cloudposture.config import ScanConfig
from cloudposture.models import Finding, Severity, Status

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class CheckSpec:
    id: str
    service: str
    title: str
    description: str
    severity: Severity
    expected: str
    remediation: tuple[str, ...]

    @property
    def mappings(self):
        return MAPPINGS[self.id]


class FindingFactory:
    """Builds findings pre-filled with the spec's static metadata."""

    def __init__(self, spec: CheckSpec):
        self.spec = spec

    def _make(self, status: Status, resource: str, current: str, region: str, expected: str | None) -> Finding:
        s = self.spec
        return Finding(
            check_id=s.id,
            service=s.service,
            resource=resource,
            region=region,
            severity=s.severity,
            title=s.title,
            description=s.description,
            current_state=current,
            expected_state=expected or s.expected,
            status=status,
            remediation=list(s.remediation),
            mappings={fw: list(ms) for fw, ms in s.mappings.items()},
        )

    def passed(self, resource: str, current: str, region: str = "global", expected: str | None = None) -> Finding:
        return self._make(Status.PASS, resource, current, region, expected)

    def failed(self, resource: str, current: str, region: str = "global", expected: str | None = None) -> Finding:
        return self._make(Status.FAIL, resource, current, region, expected)

    def not_applicable(self, resource: str, current: str, region: str = "global") -> Finding:
        return self._make(Status.NOT_APPLICABLE, resource, current, region, None)

    def error(self, resource: str, message: str, region: str = "global") -> Finding:
        return self._make(Status.ERROR, resource, f"Could not evaluate: {message}", region, None)

    def evaluate(self, ok: bool, resource: str, current: str, region: str = "global") -> Finding:
        return (self.passed if ok else self.failed)(resource, current, region)


CheckFunc = Callable[["ScanContext", FindingFactory], list[Finding]]


@dataclass(frozen=True)
class RegisteredCheck:
    spec: CheckSpec
    func: CheckFunc


REGISTRY: dict[str, RegisteredCheck] = {}


def check(
    *,
    id: str,
    service: str,
    title: str,
    description: str,
    severity: Severity,
    expected: str,
    remediation: list[str],
) -> Callable[[CheckFunc], CheckFunc]:
    """Register a check. Fails fast if its compliance mapping is missing."""

    def decorator(func: CheckFunc) -> CheckFunc:
        if id in REGISTRY:
            raise ValueError(f"Duplicate check id {id}")
        if id not in MAPPINGS:
            raise ValueError(f"Check {id} has no entry in compliance/mappings.py")
        spec = CheckSpec(id, service, title, description, severity, expected, tuple(remediation))
        REGISTRY[id] = RegisteredCheck(spec, func)
        return func

    return decorator


@dataclass
class ScanContext:
    """Shared state for one scan: clients, config and memoised API results."""

    clients: AwsClients
    config: ScanConfig
    _cache: dict[str, Any] = field(default_factory=dict)

    def client(self, service: str, region: str | None = None) -> Any:
        return self.clients.client(service, region)

    @property
    def account_id(self) -> str:
        return self.clients.account_id

    @property
    def regions(self) -> list[str]:
        return self.memo("regions", lambda: self.config.regions or self.clients.enabled_regions())

    def memo(self, key: str, factory: Callable[[], Any]) -> Any:
        if key not in self._cache:
            self._cache[key] = factory()
        return self._cache[key]


def error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def per_region(ctx: ScanContext, f: FindingFactory, fn: Callable[[str], list[Finding]]) -> list[Finding]:
    """Run ``fn(region)`` in every region; a failing region becomes one ERROR finding."""
    out: list[Finding] = []
    for region in ctx.regions:
        try:
            out.extend(fn(region))
        except ClientError as exc:
            log.warning("%s failed in %s: %s", f.spec.id, region, exc)
            out.append(f.error(f"region/{region}", f"{error_code(exc)} in {region}", region))
    return out
