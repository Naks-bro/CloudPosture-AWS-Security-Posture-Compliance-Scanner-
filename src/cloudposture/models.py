"""Structured result models shared by the scanner, reporting layer and dashboard."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Framework identifiers (keys used in mappings, summaries and the UI).
CIS = "CIS"
ISO27001 = "ISO27001"
PCI_DSS = "PCI_DSS"
SOC2 = "SOC2"

FRAMEWORKS: dict[str, str] = {
    CIS: "CIS AWS Foundations Benchmark v3.0.0",
    ISO27001: "ISO/IEC 27001:2022 Annex A",
    PCI_DSS: "PCI DSS v4.0",
    SOC2: "SOC 2 (2017 Trust Services Criteria)",
}


class Status(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    ERROR = "ERROR"  # check could not be evaluated (e.g. AccessDenied) - never counted as pass
    NOT_APPLICABLE = "N/A"  # nothing to evaluate (e.g. no S3 buckets exist)


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]

    @property
    def weight(self) -> int:
        """Weight used by the severity-weighted score."""
        return {"CRITICAL": 10, "HIGH": 6, "MEDIUM": 3, "LOW": 1}[self.value]


SEVERITY_ORDER = [s.value for s in sorted(Severity, key=lambda s: -s.rank)]


@dataclass(frozen=True)
class Mapping:
    """A reference from a check to one control of a compliance framework.

    ``confidence`` is "exact" when the control directly describes the same
    requirement, "approximate" when the link is thematic (see docs/MAPPINGS.md).
    """

    control_id: str
    title: str
    confidence: str = "approximate"

    def label(self) -> str:
        return f"{self.control_id} ({self.confidence})"

    def to_dict(self) -> dict[str, str]:
        return {"control_id": self.control_id, "title": self.title, "confidence": self.confidence}


@dataclass
class Finding:
    check_id: str
    service: str
    resource: str
    region: str
    severity: Severity
    title: str
    description: str
    current_state: str
    expected_state: str
    status: Status
    remediation: list[str]
    mappings: dict[str, list[Mapping]] = field(default_factory=dict)

    # -- convenience -------------------------------------------------------
    def mapping_labels(self, framework: str) -> list[str]:
        return [m.label() for m in self.mappings.get(framework, [])]

    def mapped_to(self, framework: str) -> bool:
        return bool(self.mappings.get(framework))

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "service": self.service,
            "resource": self.resource,
            "region": self.region,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "current_state": self.current_state,
            "expected_state": self.expected_state,
            "status": self.status.value,
            "remediation": list(self.remediation),
            "mappings": {fw: [m.to_dict() for m in ms] for fw, ms in self.mappings.items()},
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            check_id=d["check_id"],
            service=d["service"],
            resource=d["resource"],
            region=d.get("region", "global"),
            severity=Severity(d["severity"]),
            title=d["title"],
            description=d["description"],
            current_state=d["current_state"],
            expected_state=d["expected_state"],
            status=Status(d["status"]),
            remediation=list(d.get("remediation", [])),
            mappings={
                fw: [Mapping(**m) for m in ms] for fw, ms in d.get("mappings", {}).items()
            },
        )


@dataclass
class ScanMetadata:
    mode: str = "live"  # "live" | "demo"
    account_id: str = "unknown"
    regions: list[str] = field(default_factory=list)
    started_at: str = ""
    duration_seconds: float = 0.0
    tool_version: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class ScanResult:
    findings: list[Finding]
    metadata: ScanMetadata = field(default_factory=ScanMetadata)

    def to_dict(self) -> dict[str, Any]:
        return {"metadata": self.metadata.to_dict(), "findings": [f.to_dict() for f in self.findings]}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "ScanResult":
        return cls(
            findings=[Finding.from_dict(f) for f in d["findings"]],
            metadata=ScanMetadata(**d.get("metadata", {})),
        )
