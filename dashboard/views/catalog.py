"""Check catalog: every implemented check with its latest status and control references."""
from __future__ import annotations

import streamlit as st

from cloudposture.checks import REGISTRY
from cloudposture.models import SEVERITY_ORDER, Finding, Status
from cloudposture.scoring import check_statuses
from dashboard import components as c
from dashboard.data import catalog_frame
from dashboard.theme import SEVERITY_COLORS, STATUS_COLORS


def render(findings: list[Finding]) -> None:
    specs = sorted((rc.spec for rc in REGISTRY.values()), key=lambda s: s.id)
    statuses = check_statuses(findings)
    counts: dict[str, list[int]] = {}
    for f in findings:
        p = counts.setdefault(f.check_id, [0, 0])
        p[0] += f.status is Status.PASS
        p[1] += f.status is Status.FAIL
    df = catalog_frame(specs, statuses, {k: (v[0], v[1]) for k, v in counts.items()})

    f1, f2, f3, f4 = st.columns([1.2, 1.2, 1.2, 1.6])
    svc = f1.multiselect("Service", sorted(df["Service"].unique()), default=sorted(df["Service"].unique()), key="c_svc")
    sev = f2.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER, key="c_sev")
    stat = f3.multiselect("Status", ["FAIL", "ERROR", "PASS", "N/A", "NOT RUN"],
                          default=["FAIL", "ERROR", "PASS", "N/A", "NOT RUN"], key="c_status")
    q = f4.text_input("Search", placeholder="id, title or control…", key="c_q").strip().lower()
    view = df[df["Service"].isin(svc) & df["Severity"].isin(sev) & df["Status"].isin(stat)]
    if q:
        view = view[view.apply(lambda r: q in " ".join(map(str, r.values)).lower(), axis=1)]

    st.caption(f"**{len(view)}** of {len(df)} checks · Status = worst result across the check's resources · "
               f"ISO 27001, PCI DSS and SOC 2 columns are **{c.APPROX_LABEL.lower()}** (indicative only)")
    styled = (view.style.map(lambda v: f"color:{STATUS_COLORS.get(v, '#8b95a8')};font-weight:700", subset=["Status"])
              .map(lambda v: f"color:{SEVERITY_COLORS.get(v, '#e6e9ef')};font-weight:600", subset=["Severity"]))
    st.dataframe(styled, hide_index=True, width="stretch", height=min(760, 38 + 35 * max(len(view), 1)), column_config={
        "ID": st.column_config.TextColumn(width="small"), "Service": st.column_config.TextColumn(width="small"),
        "Check": st.column_config.TextColumn(width=470), "Severity": st.column_config.TextColumn(width="small"),
        "Status": st.column_config.TextColumn(width="small"), "Pass / Fail": st.column_config.TextColumn(width="small"),
    })
