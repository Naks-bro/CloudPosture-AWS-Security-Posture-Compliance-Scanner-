"""CloudPosture Streamlit dashboard.   Run:  streamlit run dashboard/app.py"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "src")]  # works with or without `pip install -e .`

import boto3  # noqa: E402
import streamlit as st  # noqa: E402

from cloudposture import __version__  # noqa: E402
from cloudposture.config import ScanConfig, load_dotenv  # noqa: E402
from cloudposture.models import FRAMEWORKS, SEVERITY_ORDER, ScanResult, Status  # noqa: E402
from cloudposture.reporting import findings_to_csv, load_json, result_to_json  # noqa: E402
from cloudposture.scoring import summarize  # noqa: E402
from dashboard import charts  # noqa: E402
from dashboard.data import apply_filters, remediation_groups, to_frame  # noqa: E402
from dashboard.styles import COLORS, CSS, SEVERITY_COLORS, score_color  # noqa: E402

SAMPLE = ROOT / "sample_data" / "sample_scan.json"

st.set_page_config(page_title="CloudPosture | AWS Security Posture", page_icon="🛡️", layout="wide")
st.markdown(CSS, unsafe_allow_html=True)
load_dotenv(ROOT / ".env")


# ----------------------------------------------------------------------------- helpers
def card(label: str, value: str, hint: str = "", color: str = "#e5e9f0") -> str:
    return (f'<div class="cp-card"><div class="label">{label}</div>'
            f'<div class="value" style="color:{color}">{value}</div><div class="hint">{hint}</div></div>')


def pct(v: float | None) -> str:
    return "n/a" if v is None else f"{v:.1f}%"


def md(text: str) -> str:
    """Escape markdown metacharacters in scanner-provided text (e.g. the literal "*:*")."""
    for ch in ("\\", "*", "_", "`", "#", "<", ">"):
        text = text.replace(ch, "\\" + ch)
    return text


def section(title: str) -> None:
    st.markdown(f'<div class="cp-section">{title}</div>', unsafe_allow_html=True)


@st.cache_data(show_spinner=False)
def load_demo() -> ScanResult:
    return load_json(SAMPLE)


# ----------------------------------------------------------------------------- sidebar: data source
with st.sidebar:
    st.markdown("### 🛡️ CloudPosture")
    st.caption(f"v{__version__} · read-only AWS scanner")
    source = st.radio("Data source", ["Demo data", "Live AWS scan", "Upload scan JSON"], index=0)

    if source == "Live AWS scan":
        st.info("Read-only: the scanner blocks every non-Get/List/Describe API call. "
                "Credentials come from your AWS profile / environment - never typed here.")
        env_cfg = ScanConfig.from_env()
        profiles = ["(default credential chain)"] + sorted(boto3.Session().available_profiles)
        default_idx = profiles.index(env_cfg.profile) if env_cfg.profile in profiles else 0
        profile = st.selectbox("AWS profile", profiles, index=default_idx)
        home_region = st.text_input("Home region", env_cfg.home_region)
        regions = st.text_input("Regions to scan (comma-separated, blank = all enabled)", ",".join(env_cfg.regions))
        services = st.multiselect("Services", ["IAM", "S3", "EC2", "CloudTrail"],
                                  default=["IAM", "S3", "EC2", "CloudTrail"])
        if st.button("Run scan", type="primary", width="stretch"):
            from cloudposture.scanner import run_scan

            cfg = ScanConfig.from_env()
            cfg.profile = None if profile.startswith("(") else profile
            cfg.home_region = home_region.strip() or cfg.home_region
            cfg.regions = [r.strip() for r in regions.split(",") if r.strip()]
            try:
                with st.spinner("Scanning AWS (read-only)... this can take a minute"):
                    st.session_state["live_result"] = run_scan(cfg, services=services or None)
            except Exception as exc:  # credentials/network problems should not crash the page
                st.session_state.pop("live_result", None)
                st.error(f"Scan failed: {type(exc).__name__}: {exc}")
        result: ScanResult | None = st.session_state.get("live_result")
    elif source == "Upload scan JSON":
        up = st.file_uploader("CloudPosture JSON export", type="json")
        result = None
        if up is not None:
            try:
                import json
                result = ScanResult.from_dict(json.load(up))
            except (ValueError, KeyError) as exc:
                st.error(f"Not a valid CloudPosture export: {exc}")
    else:
        result = load_demo()

if result is None:
    st.markdown('<div class="cp-header"><div><div class="cp-title">Cloud<span>Posture</span></div>'
                '<div class="cp-sub">AWS Security Posture &amp; Compliance Scanner</div></div></div>',
                unsafe_allow_html=True)
    if source == "Live AWS scan":
        st.info("Pick a profile and click **Run scan** in the sidebar. Nothing is modified in your account.")
    else:
        st.info("Choose a data source in the sidebar. Use **Demo data** to explore without AWS credentials.")
    st.stop()

meta, findings = result.metadata, result.findings
summary = summarize(findings)

# ----------------------------------------------------------------------------- header
badge = '<span class="cp-badge demo">DEMO DATA</span>' if meta.mode == "demo" else '<span class="cp-badge live">LIVE SCAN</span>'
st.markdown(
    f'<div class="cp-header"><div><div class="cp-title">Cloud<span>Posture</span></div>'
    f'<div class="cp-sub">AWS Security Posture &amp; Compliance Scanner · account <b>{meta.account_id}</b> · '
    f'{meta.started_at or "n/a"} · {len(meta.regions) or "n/a"} region(s)</div></div>'
    f'<div>{badge}<span class="cp-badge ro">READ-ONLY</span></div></div>',
    unsafe_allow_html=True,
)
if meta.mode == "demo":
    st.warning(meta.notes[0] if meta.notes else "Demo data - not a real AWS account.", icon="⚠️")
for note in meta.notes if meta.mode != "demo" else []:
    st.caption(note)
if summary.errors:
    st.warning(f"{summary.errors} finding(s) could not be evaluated (permissions or API errors). "
               "They are excluded from the scores - see status ERROR in the table.")

# ----------------------------------------------------------------------------- KPIs
k = st.columns(5)
k[0].markdown(card("Posture score", pct(summary.pass_rate), f"Severity-weighted: {pct(summary.weighted_score)}",
                   score_color(summary.pass_rate)), unsafe_allow_html=True)
k[1].markdown(card("Total checks", str(summary.checks_total), f"{summary.scored} resource-level findings"),
              unsafe_allow_html=True)
k[2].markdown(card("Passed", str(summary.passed), f"{summary.checks_passed} checks fully passing", COLORS["pass"]),
              unsafe_allow_html=True)
k[3].markdown(card("Failed", str(summary.failed), f"{summary.checks_total - summary.checks_passed} checks with failures",
                   COLORS["fail"]), unsafe_allow_html=True)
k[4].markdown(card("Not scored", str(summary.errors + summary.not_applicable),
                   f"{summary.errors} errors · {summary.not_applicable} n/a", COLORS["muted"]), unsafe_allow_html=True)

# ----------------------------------------------------------------------------- charts
section("Posture overview")
c1, c2, c3 = st.columns([1, 1.2, 1.3])
with c1:
    st.caption("Overall pass rate")
    st.plotly_chart(charts.score_gauge(summary.pass_rate), width="stretch", config={"displayModeBar": False})
with c2:
    st.caption("Failed findings by severity")
    st.plotly_chart(charts.severity_chart(summary), width="stretch", config={"displayModeBar": False})
with c3:
    st.caption("Results by service")
    st.plotly_chart(charts.service_chart(summary), width="stretch", config={"displayModeBar": False})

# ----------------------------------------------------------------------------- frameworks
section("Framework compliance")
st.caption("Pass rate over the checks mapped to each framework. CIS numbers are direct; ISO 27001, PCI DSS and SOC 2 "
           "links are **approximate thematic mappings** (see docs/MAPPINGS.md) - evidence, not certification.")
fcols = st.columns(len(FRAMEWORKS))
for col, fw in zip(fcols, summary.frameworks.values()):
    rate = fw.bucket.pass_rate
    width = 0 if rate is None else rate
    col.markdown(
        f'<div class="cp-card cp-fw"><div class="row"><b>{fw.name}</b></div>'
        f'<div class="value" style="font-size:1.8rem;font-weight:700;color:{score_color(rate)}">{pct(rate)}</div>'
        f'<div class="bar"><div style="width:{width}%;background:{score_color(rate)}"></div></div>'
        f'<div class="meta">{fw.bucket.passed} passed · {fw.bucket.failed} failed<br>'
        f'{fw.checks_mapped} of {fw.checks_total} checks mapped ({fw.coverage_pct:.0f}%)</div></div>',
        unsafe_allow_html=True)

# ----------------------------------------------------------------------------- filters + table
section("Findings")
all_services = sorted({f.service for f in findings})
f1, f2, f3, f4 = st.columns([1.2, 1.2, 1.2, 1.4])
sel_services = f1.multiselect("Service", all_services, default=all_services)
sel_sev = f2.multiselect("Severity", SEVERITY_ORDER, default=SEVERITY_ORDER)
sel_status = f3.multiselect("Status", [s.value for s in Status], default=["FAIL", "ERROR"] if summary.failed else [s.value for s in Status])
text = f4.text_input("Search", placeholder="resource, check id, title…")
filtered = apply_filters(findings, sel_services, sel_sev, sel_status, text)

df = to_frame(filtered)
st.caption(f"Showing {len(filtered)} of {len(findings)} findings")


def _style_status(v: str) -> str:
    color = {"PASS": COLORS["pass"], "FAIL": COLORS["fail"], "ERROR": COLORS["error"]}.get(v, COLORS["na"])
    return f"color:{color};font-weight:700"


def _style_sev(v: str) -> str:
    return f"color:{SEVERITY_COLORS.get(v, '#e5e9f0')};font-weight:600"


if df.empty:
    st.info("No findings match the current filters.")
else:
    styled = df.style.map(_style_status, subset=["Status"]).map(_style_sev, subset=["Severity"])
    st.dataframe(styled, width="stretch", height=420, hide_index=True)

stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
d1, d2, _ = st.columns([1, 1, 3])
d1.download_button("⬇ Export filtered CSV", findings_to_csv(filtered), f"cloudposture_filtered_{stamp}.csv",
                   "text/csv", disabled=not filtered, width="stretch")
d2.download_button("⬇ Export full CSV", findings_to_csv(findings), f"cloudposture_full_{stamp}.csv",
                   "text/csv", width="stretch")

# ----------------------------------------------------------------------------- remediation
section("Remediation guidance")
groups = remediation_groups(filtered)
if not groups:
    st.success("Nothing to remediate in the current selection.")
for g in groups:
    head = g[0]
    n_fail = sum(x.status is Status.FAIL for x in g)
    label = md(f"[{head.severity.value}] {head.check_id} · {head.title} - {n_fail or len(g)} resource(s)")
    with st.expander(label):
        st.markdown(f"**Why it matters:** {md(head.description)}")
        st.markdown(f"**Expected state:** {md(head.expected_state)}")
        st.markdown("**Fix steps**")
        for i, step in enumerate(head.remediation, 1):
            st.markdown(f"{i}. {md(step)}")
        st.markdown("**Affected resources**")
        for x in g[:25]:
            st.markdown(f"- {md(x.resource)} ({x.region}) - {md(x.current_state)}")
        if len(g) > 25:
            st.caption(f"…and {len(g) - 25} more (see CSV export)")
        maps = []
        for key, name in (("CIS", "CIS"), ("ISO27001", "ISO 27001"), ("PCI_DSS", "PCI DSS"), ("SOC2", "SOC 2")):
            labels = head.mapping_labels(key)
            if labels:
                maps.append(f"**{name}:** {', '.join(labels)}")
        if maps:
            st.caption(" · ".join(maps))

# ----------------------------------------------------------------------------- footer
with st.expander("Scope, scoring & limitations"):
    st.markdown(
        "- **Read-only:** only Get/List/Describe calls (plus `GenerateCredentialReport`) are possible; mutating calls are blocked in code.\n"
        "- **Scoring:** only PASS/FAIL are scored. ERROR (could not evaluate) and N/A never count as passes. "
        "Pass rate = passed ÷ (passed + failed) at resource level; the weighted score uses CRITICAL 10 / HIGH 6 / MEDIUM 3 / LOW 1.\n"
        "- **Not covered:** CIS controls that need data not exposed by read APIs (e.g. manual/organisational controls), "
        "AWS-managed `AdministratorAccess`, RDS, VPC flow logs, CloudWatch metric-filter alarms.\n"
        "- Passing these checks is not a compliance certification."
    )
    st.download_button("Download scan JSON", result_to_json(result), f"cloudposture_{stamp}.json", "application/json")
