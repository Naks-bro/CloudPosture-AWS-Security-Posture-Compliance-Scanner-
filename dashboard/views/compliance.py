"""Compliance tab: per-framework posture with explicit mapping-confidence labelling."""
from __future__ import annotations

import pandas as pd
import streamlit as st

from cloudposture.models import Finding
from cloudposture.scoring import Summary, control_rows
from dashboard import components as c


def render(findings: list[Finding], summary: Summary) -> None:
    c.render(c.COMPLIANCE_NOTICE)
    cards = "".join(c.framework_card(findings, fw) for fw in summary.frameworks.values())
    c.render(f'<div class="cp-grid4">{cards}</div>')

    c.render(c.heading("Control-level results", "PASS/FAIL findings of the checks mapped to each control"))
    key = st.segmented_control("Framework", list(c.FW_SHORT), default="CIS", format_func=c.FW_SHORT.get,
                               key="compliance_fw") or "CIS"
    if key != "CIS":
        st.caption(f"{c.APPROX_LABEL}: control references for {c.FW_SHORT[key]} are indicative, not authoritative.")
    rows = control_rows(findings, key)
    df = pd.DataFrame([{
        "Control": r.control_id, "Description": r.title,
        "Mapping": "Exact" if r.confidence == "exact" else c.APPROX_LABEL,
        "Pass rate": r.pass_rate if r.pass_rate is not None else None,
        "Passed": r.passed, "Failed": r.failed, "Checks": ", ".join(r.checks),
    } for r in rows])
    if df.empty:
        st.info("No mapped findings for this framework.")
        return
    st.dataframe(df, hide_index=True, width="stretch", height=min(560, 38 + 35 * len(df)), column_config={
        "Pass rate": st.column_config.ProgressColumn(format="%.0f%%", min_value=0, max_value=100),
        "Control": st.column_config.TextColumn(width="small"),
        "Description": st.column_config.TextColumn(width="large"),
        "Mapping": st.column_config.TextColumn(width="medium"),
        "Passed": st.column_config.NumberColumn(width="small"), "Failed": st.column_config.NumberColumn(width="small"),
    })
