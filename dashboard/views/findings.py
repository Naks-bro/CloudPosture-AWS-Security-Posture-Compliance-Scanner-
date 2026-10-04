"""Findings explorer: filters, readable table, and a full detail panel for the selected row."""
from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import streamlit as st

from cloudposture.checks import REGISTRY
from cloudposture.models import FRAMEWORKS, SEVERITY_ORDER, Finding, Status
from cloudposture.reporting import findings_to_csv
from dashboard import components as c
from dashboard.data import apply_filters, findings_frame, sort_findings
from dashboard.theme import SEVERITY_COLORS, STATUS_COLORS


def _status_style(v: str) -> str:
    return f"color:{STATUS_COLORS.get(v, '#8b95a8')};font-weight:700"


def _sev_style(v: str) -> str:
    return f"color:{SEVERITY_COLORS.get(v, '#e6e9ef')};font-weight:600"


def _row_tint(row: pd.Series) -> list[str]:
    return ["background-color:rgba(255,77,106,0.09)" if row["Status"] == "FAIL" else ""] * len(row)


def render(findings: list[Finding], has_failures: bool) -> None:
    present_ids = sorted({f.check_id for f in findings})
    services = sorted({f.service for f in findings})
    c1, c2, c3 = st.columns(3)
    statuses = c1.multiselect("Status", [s.value for s in Status], default=["FAIL", "ERROR"] if has_failures else [s.value for s in Status], key="f_status")
    severities = c2.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER, key="f_sev")
    svc = c3.multiselect("Service", services, default=services, key="f_svc")
    c4, c5, c6 = st.columns([2, 1.2, 1.2])
    checks = c4.multiselect("Check", present_ids, default=[], key="f_check", placeholder="All checks",
                            format_func=lambda i: f"{i} · {REGISTRY[i].spec.title}" if i in REGISTRY else i)
    fw_label = {"": "All frameworks", **{k: v for k, v in c.FW_SHORT.items()}}
    framework = c5.selectbox("Framework", list(fw_label), format_func=fw_label.get, key="f_fw")
    text = c6.text_input("Search", placeholder="resource, check, state…", key="f_text")

    shown = sort_findings(apply_filters(findings, set(svc), set(severities), set(statuses),
                                        set(checks) or None, framework or None, text))
    top = st.columns([4, 1.3])
    top[0].caption(f"Showing **{len(shown)}** of {len(findings)} findings · click a row to inspect it")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    top[1].download_button("Export filtered CSV", findings_to_csv(shown), f"cloudposture_filtered_{stamp}.csv",
                           "text/csv", disabled=not shown, width="stretch", key="dl_filtered")
    if not shown:
        st.info("No findings match the current filters.")
        return

    df = findings_frame(shown)
    styled = df.style.apply(_row_tint, axis=1).map(_status_style, subset=["Status"]).map(_sev_style, subset=["Severity"])
    event = st.dataframe(
        styled, hide_index=True, width="stretch", height=min(430, 38 + 35 * len(df)),
        on_select="rerun", selection_mode="single-row", key="findings_table",
        column_config={
            "Status": st.column_config.TextColumn(width="small"), "Severity": st.column_config.TextColumn(width="small"),
            "Service": st.column_config.TextColumn(width="small"), "Check": st.column_config.TextColumn(width="small"),
            "Resource": st.column_config.TextColumn(width="medium"), "Region": st.column_config.TextColumn(width="small"),
            "Current state": st.column_config.TextColumn(width="large"),
        },
    )
    rows = event.selection.rows
    idx = rows[0] if rows and rows[0] < len(shown) else 0
    c.render(c.heading("Finding details", "selected row" if rows else "first finding shown - click a row above to inspect another"))
    c.render(c.finding_detail(shown[idx]))
