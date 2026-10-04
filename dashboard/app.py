"""CloudPosture dashboard.   Run:  streamlit run dashboard/app.py"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]  # works with or without `pip install -e .`

import streamlit as st  # noqa: E402

from cloudposture.config import load_dotenv  # noqa: E402
from cloudposture.scoring import summarize  # noqa: E402
from dashboard import components as c, sidebar  # noqa: E402
from dashboard.theme import CSS  # noqa: E402
from dashboard.views import catalog, compliance, findings, overview, reports, services  # noqa: E402

st.set_page_config(page_title="CloudPosture · AWS Security Posture", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)
load_dotenv(ROOT / ".env")

source, result = sidebar.render()

if result is None:
    c.render('<div class="cp-top"><div><div class="cp-title">Cloud<b>Posture</b></div>'
             '<div class="cp-tag">AWS Security Posture &amp; Compliance Scanner</div></div></div>')
    if source == "Live AWS":
        st.info("Choose a profile and click **Run security scan** in the sidebar. The scan is read-only: "
                "CloudPosture does not modify AWS resources.")
    else:
        st.info("Upload a CloudPosture scan JSON in the sidebar, or switch to **Demo Data**.")
    st.stop()

summary = summarize(result.findings)
c.render(c.header(result.metadata, summary))

tab_names = ["Overview", "Findings", "Compliance", "Services", "Check catalog", "Reports"]
t_over, t_find, t_comp, t_svc, t_cat, t_rep = st.tabs(tab_names)
with t_over:
    overview.render(result.findings, summary)
with t_find:
    findings.render(result.findings, summary.failed > 0)
with t_comp:
    compliance.render(result.findings, summary)
with t_svc:
    services.render(result.findings)
with t_cat:
    catalog.render(result.findings)
with t_rep:
    reports.render(result)
