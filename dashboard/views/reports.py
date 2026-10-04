"""Reports tab: obvious, labelled exports."""
from __future__ import annotations

from datetime import datetime, timezone

import streamlit as st

from cloudposture.models import ScanResult
from cloudposture.reporting import CSV_COLUMNS, findings_to_csv, result_to_json
from dashboard import components as c


def render(result: ScanResult) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    mode = result.metadata.mode
    n = len(result.findings)
    left, right = st.columns(2, gap="medium")
    with left:
        c.render(c.heading("Findings CSV"))
        c.render(f'<div class="cp-panel"><div class="cp-sub" style="margin:0 0 .6rem">One row per finding ({n} rows) with '
                 'status, severity, current/expected state, remediation and CIS / ISO 27001 / PCI DSS / SOC 2 mappings '
                 '(with confidence). Spreadsheet-safe.</div></div>')
        st.download_button("Export findings CSV", findings_to_csv(result.findings), f"cloudposture_{mode}_{stamp}.csv",
                           "text/csv", type="primary", width="stretch", key="dl_csv")
    with right:
        c.render(c.heading("Scan JSON"))
        c.render('<div class="cp-panel"><div class="cp-sub" style="margin:0 0 .6rem">Complete scan including metadata and '
                 'structured mappings. Re-load it later with <b>Upload</b> in the sidebar.</div></div>')
        st.download_button("Export scan JSON", result_to_json(result), f"cloudposture_{mode}_{stamp}.json",
                           "application/json", type="primary", width="stretch", key="dl_json")
    c.render(c.heading("CSV columns"))
    st.code(", ".join(CSV_COLUMNS), language=None, wrap_lines=True)
    c.render(c.heading("From the command line"))
    st.code("python -m cloudposture scan --profile <readonly-profile>   # writes CSV + JSON to reports/", language="bash")
    if mode != "demo":
        st.caption("Exports contain account IDs and resource names - handle them as sensitive.")
