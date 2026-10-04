"""CSV / JSON export. Pure functions: no AWS access."""
from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from cloudposture.models import FRAMEWORKS, CIS, ISO27001, PCI_DSS, SOC2, Finding, ScanResult

CSV_COLUMNS = [
    "check_id", "service", "region", "resource", "severity", "status", "title", "description",
    "current_state", "expected_state", "remediation",
    "cis_mapping", "iso27001_mapping", "pci_dss_mapping", "soc2_mapping",
]
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe(value: str) -> str:
    """Neutralise spreadsheet formula injection (resource names/tags are attacker-influenced)."""
    return "'" + value if value.startswith(_FORMULA_PREFIXES) else value


def finding_to_row(f: Finding) -> dict[str, str]:
    row = {
        "check_id": f.check_id, "service": f.service, "region": f.region, "resource": f.resource,
        "severity": f.severity.value, "status": f.status.value, "title": f.title,
        "description": f.description, "current_state": f.current_state, "expected_state": f.expected_state,
        "remediation": " | ".join(f"{i}. {s}" for i, s in enumerate(f.remediation, 1)),
        "cis_mapping": "; ".join(f.mapping_labels(CIS)),
        "iso27001_mapping": "; ".join(f.mapping_labels(ISO27001)),
        "pci_dss_mapping": "; ".join(f.mapping_labels(PCI_DSS)),
        "soc2_mapping": "; ".join(f.mapping_labels(SOC2)),
    }
    return {k: _safe(v) for k, v in row.items()}


def findings_to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for f in findings:
        writer.writerow(finding_to_row(f))
    return buf.getvalue()


def write_csv(findings: list[Finding], path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(findings_to_csv(findings), encoding="utf-8")
    return p


def result_to_json(result: ScanResult) -> str:
    payload = result.to_dict()
    payload["frameworks"] = FRAMEWORKS
    return json.dumps(payload, indent=2)


def write_json(result: ScanResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(result_to_json(result), encoding="utf-8")
    return p


def load_json(path: str | Path) -> ScanResult:
    return ScanResult.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
