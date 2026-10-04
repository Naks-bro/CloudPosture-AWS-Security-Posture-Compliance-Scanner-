"""Data helpers for the UI: ordering, filtering and DataFrame construction (no scoring logic here)."""
from __future__ import annotations

import pandas as pd

from cloudposture.models import CIS, ISO27001, PCI_DSS, SOC2, Finding, Status

_STATUS_ORDER = {"FAIL": 0, "ERROR": 1, "PASS": 2, "N/A": 3}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Failures first, then by severity, check and resource."""
    return sorted(findings, key=lambda f: (_STATUS_ORDER[f.status.value], -f.severity.rank, f.check_id, f.resource))


def apply_filters(
    findings: list[Finding],
    services=None, severities=None, statuses=None, check_ids=None, framework: str | None = None, text: str = "",
) -> list[Finding]:
    """Each argument is optional; ``None`` means "no restriction"."""
    text = text.strip().lower()
    out = []
    for f in findings:
        if services is not None and f.service not in services:
            continue
        if severities is not None and f.severity.value not in severities:
            continue
        if statuses is not None and f.status.value not in statuses:
            continue
        if check_ids is not None and f.check_id not in check_ids:
            continue
        if framework and not f.mapped_to(framework):
            continue
        if text and text not in f"{f.check_id} {f.title} {f.resource} {f.current_state}".lower():
            continue
        out.append(f)
    return out


FINDING_COLUMNS = ["Status", "Severity", "Service", "Check", "Resource", "Region", "Current state"]


def findings_frame(findings: list[Finding]) -> pd.DataFrame:
    """Row order == ``findings`` order, so a selected row index maps back to ``findings[i]``."""
    return pd.DataFrame(
        [{"Status": f.status.value, "Severity": f.severity.value, "Service": f.service, "Check": f.check_id,
          "Resource": f.resource, "Region": f.region, "Current state": f.current_state} for f in findings],
        columns=FINDING_COLUMNS,
    )


def _ids(f_or_spec, fw) -> str:
    return ", ".join(m.control_id for m in f_or_spec.mappings.get(fw, [])) or "-"


def catalog_frame(specs, statuses: dict[str, Status], result_counts: dict[str, tuple[int, int]]) -> pd.DataFrame:
    """One row per registered check; status is 'NOT RUN' if the check was not part of the scan."""
    rows = []
    for s in specs:
        st = statuses.get(s.id)
        p, f = result_counts.get(s.id, (0, 0))
        rows.append({
            "ID": s.id, "Service": s.service, "Check": s.title, "Severity": s.severity.value,
            "Status": st.value if st else "NOT RUN", "Pass / Fail": f"{p} / {f}" if st else "-",
            "CIS": _ids(s, CIS), "ISO 27001 (approx.)": _ids(s, ISO27001),
            "PCI DSS (approx.)": _ids(s, PCI_DSS), "SOC 2 (approx.)": _ids(s, SOC2),
        })
    return pd.DataFrame(rows)
