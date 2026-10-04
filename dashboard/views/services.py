"""Services tab: posture per AWS service."""
from __future__ import annotations

import streamlit as st

from cloudposture.models import Finding
from cloudposture.scoring import service_breakdown
from dashboard import charts, components as c


def render(findings: list[Finding]) -> None:
    stats = service_breakdown(findings)
    c.render(f'<div class="cp-grid4">{"".join(c.service_card(s) for s in stats.values())}</div>')
    left, right = st.columns(2, gap="medium")
    cfg = {"displayModeBar": False}
    with left:
        c.render(c.heading("Results by service", "where are the failures?"))
        st.plotly_chart(charts.results_by_service(stats), width="stretch", config=cfg)
    with right:
        c.render(c.heading("Failed findings by severity", "how serious are they?"))
        st.plotly_chart(charts.failures_by_severity(stats), width="stretch", config=cfg)
