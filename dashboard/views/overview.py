"""Overview tab: executive summary - everything a reader needs on the first screen."""
from __future__ import annotations

import streamlit as st

from cloudposture.models import Finding
from cloudposture.scoring import Summary
from dashboard import components as c


def render(findings: list[Finding], summary: Summary) -> None:
    c.render(c.hero(summary))
    c.render(c.severity_strip(summary))
    left, right = st.columns([3, 2], gap="medium")
    with left:
        c.render(c.heading("Priority findings", "failed, most severe first"))
        c.render(f'<div class="cp-panel list">{c.priority_findings(findings)}</div>')
    with right:
        c.render(c.heading("Framework compliance", "pass rate over mapped checks"))
        c.render(f'<div class="cp-panel">{c.framework_bars(summary)}'
                 '<div class="cp-sub">ISO 27001, PCI DSS and SOC 2 use approximate / thematic mappings - '
                 'indicative only, not certification evidence.</div></div>')
