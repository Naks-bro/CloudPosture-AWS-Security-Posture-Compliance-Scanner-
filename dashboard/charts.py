"""Plotly figures. Each one answers a specific security question."""
from __future__ import annotations

import plotly.graph_objects as go

from cloudposture.models import SEVERITY_ORDER
from cloudposture.scoring import ServiceStats
from dashboard.theme import SEVERITY_COLORS, STATUS_COLORS

_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font=dict(color="#c9d1e0", size=13),
    margin=dict(l=0, r=10, t=30, b=10), height=280, barmode="stack",
    legend=dict(orientation="h", y=1.14, x=0, traceorder="normal", font=dict(size=12)),
    xaxis=dict(gridcolor="#232c3f", zeroline=False), yaxis=dict(autorange="reversed", gridcolor="rgba(0,0,0,0)"),
)


def results_by_service(stats: dict[str, ServiceStats]) -> go.Figure:
    """Where are the failures? Stacked results per service."""
    names = list(stats)
    fig = go.Figure()
    for label, attr, key in (("Pass", "passed", "PASS"), ("Fail", "failed", "FAIL"),
                             ("Error", "errors", "ERROR"), ("N/A", "not_applicable", "N/A")):
        vals = [getattr(stats[n], attr) for n in names]
        fig.add_bar(name=label, y=names, x=vals, orientation="h", marker_color=STATUS_COLORS[key],
                    text=[v if v else "" for v in vals], textposition="inside", textfont=dict(color="#0b0f17", size=13),
                    hovertemplate=f"%{{y}} - {label}: %{{x}}<extra></extra>")
    fig.update_layout(**_LAYOUT, xaxis_title="Findings")
    return fig


def failures_by_severity(stats: dict[str, ServiceStats]) -> go.Figure:
    """How bad are the failures? Failed findings per service, split by severity."""
    names = list(stats)
    fig = go.Figure()
    for sev in SEVERITY_ORDER:
        vals = [stats[n].failed_by_severity[sev] for n in names]
        fig.add_bar(name=sev.title(), y=names, x=vals, orientation="h", marker_color=SEVERITY_COLORS[sev],
                    text=[v if v else "" for v in vals], textposition="inside", textfont=dict(color="#0b0f17", size=13),
                    hovertemplate=f"%{{y}} - {sev.title()}: %{{x}}<extra></extra>")
    fig.update_layout(**_LAYOUT, xaxis_title="Failed findings")
    return fig
