"""Sidebar: data source selection, live-scan form and the read-only safety statement."""
from __future__ import annotations

import json
from pathlib import Path

import boto3
import streamlit as st

from cloudposture import __version__
from cloudposture.checks import REGISTRY
from cloudposture.config import ScanConfig
from cloudposture.models import ScanResult
from cloudposture.reporting import load_json

SAMPLE = Path(__file__).resolve().parents[1] / "sample_data" / "sample_scan.json"
SOURCES = ["Demo Data", "Live AWS", "Upload"]
SERVICES = ["IAM", "S3", "EC2", "CloudTrail"]

SAFETY = (
    '<div class="cp-safe"><b>Read-only scan</b><p>CloudPosture does not modify AWS resources. Only Get / List / Describe '
    'API calls are possible; every other call is blocked in code. Credentials come from your AWS profile or '
    'environment, never from this form.</p></div>'
)


@st.cache_data(show_spinner=False)
def load_demo() -> ScanResult:
    return load_json(SAMPLE)


def render() -> tuple[str, ScanResult | None]:
    with st.sidebar:
        st.html(f'<div class="cp-brand">Cloud<b>Posture</b></div><div class="cp-brand-sub">v{__version__} · AWS security posture scanner</div>')
        source = st.segmented_control("Data source", SOURCES, default="Demo Data", key="source") or "Demo Data"
        st.html(SAFETY)

        if source == "Demo Data":
            st.caption("Bundled sample scan of a simulated account. No AWS credentials needed.")
            return source, load_demo()

        if source == "Upload":
            up = st.file_uploader("CloudPosture scan JSON", type="json", help="A file exported from the Reports tab or the CLI.")
            if up is None:
                return source, None
            try:
                return source, ScanResult.from_dict(json.load(up))
            except (ValueError, KeyError, TypeError) as exc:
                st.error(f"Not a valid CloudPosture export: {exc}")
                return source, None

        # ---- Live AWS
        env = ScanConfig.from_env()
        profiles = ["(default credential chain)"] + sorted(boto3.Session().available_profiles)
        profile = st.selectbox("AWS profile", profiles, index=profiles.index(env.profile) if env.profile in profiles else 0)
        regions = st.text_input("Regions", ",".join(env.regions), placeholder="blank = all enabled regions",
                                help="Comma-separated, e.g. us-east-1,eu-west-1. Used for EC2/EBS checks.")
        home = st.text_input("Home region", env.home_region)
        services = st.multiselect("Services", SERVICES, default=SERVICES)
        only = st.multiselect("Specific checks (optional)", sorted(REGISTRY), placeholder="All checks in selected services",
                              format_func=lambda i: f"{i} · {REGISTRY[i].spec.title}")
        if st.button("Run security scan", type="primary", width="stretch"):
            from cloudposture.scanner import run_scan  # lazy: demo mode needs no AWS setup

            cfg = ScanConfig.from_env()
            cfg.profile = None if profile.startswith("(") else profile
            cfg.home_region = home.strip() or cfg.home_region
            cfg.regions = [r.strip() for r in regions.split(",") if r.strip()]
            try:
                with st.spinner("Scanning AWS (read-only)… this can take a minute"):
                    st.session_state["live_result"] = run_scan(cfg, services=services or None, check_ids=only or None)
            except Exception as exc:  # credential / network / filter problems must not crash the page
                st.session_state.pop("live_result", None)
                st.error(f"Scan failed: {type(exc).__name__}: {exc}")
        return source, st.session_state.get("live_result")
