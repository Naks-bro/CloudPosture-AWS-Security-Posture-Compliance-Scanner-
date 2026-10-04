"""Small HTML builders. All dynamic text is escaped here - views never concatenate raw strings.

Components return HTML strings; `render()` writes them with st.html (no markdown parsing, so
characters such as '*:*' or '_' in scanner output cannot corrupt the layout).
"""
from __future__ import annotations

from html import escape as esc

import streamlit as st

from cloudposture.models import FRAMEWORKS, Finding, Status
from cloudposture.scoring import FrameworkSummary, ServiceStats, Summary, control_rows, posture_grade
from dashboard.theme import GRADE_COLORS, SEVERITY_COLORS, STATUS_COLORS, score_color

APPROX_LABEL = "Approximate / thematic mapping"
FW_SHORT = {"CIS": "CIS AWS Foundations", "ISO27001": "ISO 27001", "PCI_DSS": "PCI DSS", "SOC2": "SOC 2"}
FW_VERSION = {"CIS": "Benchmark v3.0.0", "ISO27001": "2022 · Annex A", "PCI_DSS": "v4.0", "SOC2": "2017 Trust Services Criteria"}


def render(html: str) -> None:
    st.html(html)


def pct(v: float | None, digits: int = 0) -> str:
    return "n/a" if v is None else f"{v:.{digits}f}%"


def heading(title: str, hint: str = "") -> str:
    return f'<div class="cp-h">{esc(title)}<span>{esc(hint)}</span></div>' if hint else f'<div class="cp-h">{esc(title)}</div>'


def status_badge(status: str) -> str:
    c = STATUS_COLORS.get(status, "#6b7488")
    return f'<span class="cp-badge" style="background:{c}">{esc(status)}</span>'


def severity_badge(sev: str) -> str:
    c = SEVERITY_COLORS.get(sev, "#6b7488")
    return f'<span class="cp-badge" style="background:{c}">{esc(sev)}</span>'


def confidence_tag(conf: str) -> str:
    return '<span class="cp-exact">Exact</span>' if conf == "exact" else f'<span class="cp-approx">{APPROX_LABEL}</span>'


def segmented_bar(parts: list[tuple[int, str]], title: str = "") -> str:
    total = sum(n for n, _ in parts) or 1
    segs = "".join(f'<span style="width:{100 * n / total:.2f}%;background:{c}"></span>' for n, c in parts if n)
    return f'<div class="cp-seg" role="img" aria-label="{esc(title)}">{segs}</div>'


# ----------------------------------------------------------------------------- header
def region_label(regions: list[str], limit: int = 3) -> str:
    """Compact region summary: full list when short, 'N regions' (full list in tooltip) when long."""
    if not regions:
        return "global / n/a"
    if len(regions) <= limit:
        return ", ".join(regions)
    return f"{len(regions)} regions ({', '.join(regions[:2])}, …)"


def header(meta, summary: Summary) -> str:
    live = meta.mode != "demo"
    if live:
        mode = '<span class="cp-mode live"><i></i>LIVE AWS</span>'
        account = meta.account_id
    else:
        mode = '<span class="cp-mode demo"><i></i>DEMO DATA</span>'
        account = f"{meta.account_id} (fictional)"
    if summary.errors:
        status = f"Completed with {summary.errors} error{'s' if summary.errors != 1 else ''}"
    else:
        status = "Completed" if live else "Sample scan (static)"
    ts = (meta.started_at or "n/a").replace("T", " ").replace("+00:00", " UTC")
    regions = region_label(meta.regions)
    regions_title = ", ".join(meta.regions)
    dur = f" · {meta.duration_seconds:.1f}s" if live and meta.duration_seconds else ""
    items = [("Account", account), ("Region(s)", regions), ("Last scan", ts), ("Scan status", status + dur),
             ("Scanner", f"v{meta.tool_version or 'n/a'}")]
    meta_html = "".join(
        f'<div><div class="k">{esc(k)}</div><div class="v" title="{esc(regions_title if k == "Region(s)" else "")}">{esc(v)}</div></div>'
        for k, v in items)
    banner = ""
    if not live:
        banner = ('<div class="cp-banner"><b>Demo data.</b> This is a simulated AWS account used to showcase the dashboard. '
                  'Nothing here reflects your environment. Switch to <b>Live AWS</b> in the sidebar to scan a real account.</div>')
    elif summary.errors:
        banner = ('<div class="cp-banner warn"><b>Partial results.</b> Some checks could not be evaluated (permissions or API errors). '
                  'They are excluded from the score and listed with status ERROR.</div>')
    return (
        '<div class="cp-top"><div>'
        '<div class="cp-title">Cloud<b>Posture</b></div>'
        '<div class="cp-tag">AWS Security Posture &amp; Compliance Scanner</div></div>'
        f'<div>{mode}<span class="cp-ro">READ-ONLY SCAN</span></div></div>'
        f'<div class="cp-meta">{meta_html}</div>{banner}'
    )


# ----------------------------------------------------------------------------- hero + strip
def hero(summary: Summary) -> str:
    grade = posture_grade(summary)
    gc = GRADE_COLORS[grade]
    sc = score_color(summary.pass_rate)
    value = "n/a" if summary.pass_rate is None else f"{summary.pass_rate:.0f}<small>%</small>"
    score_panel = (
        '<div class="cp-panel"><div class="cp-label">Security posture</div>'
        f'<div class="cp-score" style="color:{sc}">{value}</div>'
        f'<span class="cp-grade" style="color:{gc};border-color:{gc}66;background:{gc}14">{esc(grade)}</span>'
        f'<div class="cp-sub">Pass rate over <b>{summary.scored}</b> evaluated findings.<br>'
        f'Severity-weighted score: <b>{pct(summary.weighted_score)}</b></div></div>'
    )
    parts = [(summary.passed, STATUS_COLORS["PASS"]), (summary.failed, STATUS_COLORS["FAIL"]),
             (summary.errors, STATUS_COLORS["ERROR"]), (summary.not_applicable, STATUS_COLORS["N/A"])]
    cells = [("PASS", summary.passed, "meets expected state"), ("FAIL", summary.failed, "misconfigured"),
             ("ERROR", summary.errors, "could not evaluate"), ("N/A", summary.not_applicable, "nothing to evaluate")]
    counts = "".join(
        f'<div class="cp-count" style="border-color:{STATUS_COLORS[k]}"><div class="n" style="color:{STATUS_COLORS[k]}">{n}</div>'
        f'<div class="l">{k}</div><div class="h">{h}</div></div>' for k, n, h in cells)
    results_panel = (
        '<div class="cp-panel"><div class="cp-label">Findings by result</div>'
        f'{segmented_bar(parts, "Findings by result")}<div class="cp-counts">{counts}</div>'
        '<div class="cp-checks">'
        f'<span><b>{summary.checks_executed}</b>checks executed</span>'
        f'<span><b>{summary.checks_passed}</b>fully passing</span>'
        f'<span><b>{summary.checks_total - summary.checks_passed}</b>with failures</span>'
        f'<span><b>{summary.total_findings}</b>total findings</span></div></div>'
    )
    return f'<div class="cp-hero">{score_panel}{results_panel}</div>'


def severity_strip(summary: Summary) -> str:
    def kpi(label, n, color, hint):
        return (f'<div class="cp-kpi" style="border-left-color:{color}"><div class="l">{label}</div>'
                f'<div class="n" style="color:{color if n else "#6b7488"}">{n}</div><div class="h">{hint}</div></div>')

    sev = summary.severity
    cells = [kpi(s.title(), sev[s].failed, SEVERITY_COLORS[s], "failed findings") for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    cells.append(kpi("Total findings", summary.total_findings, "#4f8cff", "all statuses"))
    cells.append(kpi("Failed checks", summary.checks_total - summary.checks_passed, "#ff4d6a", f"of {summary.checks_executed} checks"))
    return f'<div class="cp-strip">{"".join(cells)}</div>'


# ----------------------------------------------------------------------------- overview lists
def priority_findings(findings: list[Finding], limit: int = 6) -> str:
    fails = [f for f in findings if f.status is Status.FAIL]
    fails.sort(key=lambda f: (-f.severity.rank, f.check_id, f.resource))
    if not fails:
        return '<div class="cp-sub">No failed findings.</div>'
    rows = "".join(
        f'<div class="cp-row">{severity_badge(f.severity.value)}<div><div class="t">{esc(f.title)}</div>'
        f'<div class="s"><span class="cp-mono">{esc(f.check_id)}</span> · {esc(f.resource)} · {esc(f.current_state)}</div></div></div>'
        for f in fails[:limit])
    more = f'<div class="cp-sub">+ {len(fails) - limit} more failed findings in the Findings tab.</div>' if len(fails) > limit else ""
    return rows + more


def framework_bars(summary: Summary) -> str:
    out = []
    for key, fw in summary.frameworks.items():
        rate = fw.bucket.pass_rate
        c = score_color(rate)
        tag = '<span class="cp-exact">Direct</span>' if key == "CIS" else f'<span class="cp-approx">Approximate</span>'
        out.append(
            f'<div class="cp-fwrow"><div class="top"><span><b>{esc(FW_SHORT[key])}</b>{tag}</span>'
            f'<b style="color:{c}">{pct(rate)}</b></div>'
            f'<div class="bar"><div style="width:{rate or 0}%;background:{c}"></div></div>'
            f'<div class="m">{fw.bucket.passed} passed · {fw.bucket.failed} failed · '
            f'{fw.checks_mapped}/{fw.checks_total} checks mapped</div></div>')
    return "".join(out)


# ----------------------------------------------------------------------------- compliance
def framework_card(findings: list[Finding], fw: FrameworkSummary) -> str:
    rate = fw.bucket.pass_rate
    c = score_color(rate)
    rows = control_rows(findings, fw.framework)
    approx = sum(r.confidence == "approximate" for r in rows)
    if fw.framework == "CIS":
        conf = '<span class="cp-exact">Exact CIS recommendations</span>' if not approx else \
            f'<span class="cp-exact">Mostly exact</span><span class="cp-approx">{approx} approximate</span>'
    else:
        conf = f'<span class="cp-approx">{APPROX_LABEL}</span>'
    unmapped = fw.checks_total - fw.checks_mapped
    return (
        f'<div class="cp-card"><div class="name">{esc(FW_SHORT[fw.framework])}</div>'
        f'<div class="ver">{esc(FW_VERSION[fw.framework])}</div>{conf}'
        f'<div class="rate" style="color:{c}">{pct(rate, 1)}</div>'
        f'<div class="cp-fwrow" style="margin:0"><div class="bar"><div style="width:{rate or 0}%;background:{c}"></div></div></div>'
        '<div class="cp-stats">'
        f'<div><span>Passed</span><b style="color:{STATUS_COLORS["PASS"]}">{fw.bucket.passed}</b></div>'
        f'<div><span>Failed</span><b style="color:{STATUS_COLORS["FAIL"]}">{fw.bucket.failed}</b></div>'
        f'<div><span>Mapped checks</span><b>{fw.checks_mapped}</b></div>'
        f'<div><span>Unmapped checks</span><b>{unmapped}</b></div>'
        f'<div><span>Controls covered</span><b>{len(rows)}</b></div>'
        f'<div><span>Check coverage</span><b>{fw.coverage_pct:.0f}%</b></div></div></div>'
    )


COMPLIANCE_NOTICE = (
    '<div class="cp-notice"><b>How to read this.</b> CIS references target Benchmark v3.0.0 and are direct where marked '
    '<span class="cp-exact">Exact</span>. ISO 27001, PCI DSS and SOC 2 links are '
    f'<span class="cp-approx">{APPROX_LABEL}</span>: maintainer-authored, based on control intent, with no official crosswalk. '
    'They are indicative evidence only - <b>not</b> audit or certification evidence. '
    'Unmapped checks are extra hardening checks with no corresponding control. See docs/MAPPINGS.md.</div>'
)


# ----------------------------------------------------------------------------- services
def service_card(s: ServiceStats) -> str:
    sevs = [(s.failed_by_severity[k], SEVERITY_COLORS[k]) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")]
    res = [(s.passed, STATUS_COLORS["PASS"]), (s.failed, STATUS_COLORS["FAIL"]),
           (s.errors, STATUS_COLORS["ERROR"]), (s.not_applicable, STATUS_COLORS["N/A"])]
    c = score_color(s.pass_rate)
    sev_legend = "".join(f'<span><i style="background:{col}"></i>{k.title()} {s.failed_by_severity[k]}</span>'
                         for k, (_, col) in zip(("CRITICAL", "HIGH", "MEDIUM", "LOW"), sevs))
    sev_block = (f'<div class="cp-label" style="margin-top:.9rem">Failed by severity</div>'
                 f'{segmented_bar(sevs, "Failed by severity")}<div class="cp-legend" style="margin-top:-.6rem">{sev_legend}</div>'
                 if s.failed else '<div class="cp-sub" style="margin-top:.9rem">No failed findings.</div>')
    return (
        f'<div class="cp-card"><div class="name">{esc(s.service)}</div>'
        f'<div class="rate" style="color:{c}">{pct(s.pass_rate)}</div>{segmented_bar(res, "Results")}'
        '<div class="cp-stats">'
        f'<div><span>Checks</span><b>{s.checks}</b></div>'
        f'<div><span>Pass</span><b style="color:{STATUS_COLORS["PASS"]}">{s.passed}</b></div>'
        f'<div><span>Fail</span><b style="color:{STATUS_COLORS["FAIL"]}">{s.failed}</b></div>'
        f'<div><span>Errors</span><b style="color:{STATUS_COLORS["ERROR"]}">{s.errors}</b></div></div>'
        f'{sev_block}</div>'
    )


# ----------------------------------------------------------------------------- finding detail
def finding_detail(f: Finding) -> str:
    st_key = {"PASS": "pass", "FAIL": "fail", "ERROR": "error", "N/A": "na"}[f.status.value]
    rows = []
    for key in FRAMEWORKS:
        ms = f.mappings.get(key, [])
        if not ms:
            note = "No CIS v3.0.0 recommendation (extra hardening check)" if key == "CIS" else "No mapping"
            rows.append(f'<tr><td>{esc(FW_SHORT[key])}</td><td>-</td><td>{note}</td><td></td></tr>')
        for m in ms:
            rows.append(f'<tr><td>{esc(FW_SHORT[key])}</td><td class="cp-mono">{esc(m.control_id)}</td>'
                        f'<td>{esc(m.title)}</td><td>{confidence_tag(m.confidence)}</td></tr>')
    steps = "".join(f"<li>{esc(s)}</li>" for s in f.remediation)
    approx_note = ('<div class="cp-sub" style="margin-top:.5rem">Approximate mappings are thematic and indicative only; '
                   'they are not certification evidence.</div>')
    return (
        f'<div class="cp-detail {st_key}">{status_badge(f.status.value)} {severity_badge(f.severity.value)} '
        f'<span class="cp-mono" style="margin-left:.4rem;color:#8b95a8">{esc(f.check_id)}</span>'
        f'<h3>{esc(f.title)}</h3>'
        '<div class="cp-kv">'
        f'<div><div class="k">Service</div><div class="v">{esc(f.service)}</div></div>'
        f'<div><div class="k">Resource</div><div class="v">{esc(f.resource)}</div></div>'
        f'<div><div class="k">Region</div><div class="v">{esc(f.region)}</div></div>'
        f'<div><div class="k">Severity</div><div class="v">{esc(f.severity.value)}</div></div></div>'
        '<div class="cp-cmp">'
        f'<div class="cur {st_key}"><div class="k">Current state</div>{esc(f.current_state)}</div>'
        f'<div class="exp"><div class="k">Expected state</div>{esc(f.expected_state)}</div></div>'
        f'<h4>Why it matters</h4><p>{esc(f.description)}</p>'
        f'<h4>Remediation</h4><ol>{steps}</ol>'
        '<h4>Compliance mappings</h4>'
        '<table class="cp-map"><tr><th>Framework</th><th>Control</th><th>Description</th><th>Mapping confidence</th></tr>'
        f'{"".join(rows)}</table>{approx_note}</div>'
    )
