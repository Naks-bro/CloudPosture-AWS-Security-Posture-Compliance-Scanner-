"""Data helpers: findings -> DataFrame, filtering and remediation grouping."""
from __future__ import annotations

import pandas as pd

from cloudposture.models import CIS, ISO27001, PCI_DSS, SOC2, SEVERITY_ORDER, Finding, Status

COLUMNS = ["Status", "Severity", "Service", "Check ID", "Title", "Resource", "Region",
           "Current state", "Expected state", "CIS", "ISO 27001", "PCI DSS", "SOC 2"]


def to_frame(findings: list[Finding]) -> pd.DataFrame:
    rows = [{
        "Status": f.status.value, "Severity": f.severity.value, "Service": f.service, "Check ID": f.check_id,
        "Title": f.title, "Resource": f.resource, "Region": f.region,
        "Current state": f.current_state, "Expected state": f.expected_state,
        "CIS": "; ".join(f.mapping_labels(CIS)), "ISO 27001": "; ".join(f.mapping_labels(ISO27001)),
        "PCI DSS": "; ".join(f.mapping_labels(PCI_DSS)), "SOC 2": "; ".join(f.mapping_labels(SOC2)),
    } for f in findings]
    df = pd.DataFrame(rows, columns=COLUMNS)
    if not df.empty:
        df["_sev"] = df["Severity"].map({s: i for i, s in enumerate(SEVERITY_ORDER)})
        df["_st"] = df["Status"].map({"FAIL": 0, "ERROR": 1, "PASS": 2, "N/A": 3})
        df = df.sort_values(["_st", "_sev", "Check ID", "Resource"]).drop(columns=["_sev", "_st"]).reset_index(drop=True)
    return df


def apply_filters(findings: list[Finding], services, severities, statuses, text: str) -> list[Finding]:
    text = text.strip().lower()
    out = []
    for f in findings:
        if f.service not in services or f.severity.value not in severities or f.status.value not in statuses:
            continue
        if text and text not in f"{f.check_id} {f.title} {f.resource} {f.current_state}".lower():
            continue
        out.append(f)
    return out


def remediation_groups(findings: list[Finding]):
    """Group non-passing findings by check for the remediation panel (most severe first)."""
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        if f.status in (Status.FAIL, Status.ERROR):
            groups.setdefault(f.check_id, []).append(f)
    return sorted(groups.values(), key=lambda g: (-g[0].severity.rank, g[0].check_id))
