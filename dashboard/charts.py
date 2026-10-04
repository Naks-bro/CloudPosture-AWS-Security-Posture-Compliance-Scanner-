"""Plotly figures with a consistent dark palette."""
from __future__ import annotations

import plotly.graph_objects as go

from cloudposture.models import SEVERITY_ORDER
from cloudposture.scoring import Summary
from dashboard.styles import COLORS, SEVERITY_COLORS, score_color

_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#e5e9f0", size=12), margin=dict(l=10, r=10, t=10, b=10), height=260,
)


def score_gauge(rate: float | None) -> go.Figure:
    value = rate if rate is not None else 0
    fig = go.Figure(go.Pie(
        values=[value, 100 - value], hole=0.78, sort=False, direction="clockwise", textinfo="none",
        marker=dict(colors=[score_color(rate), "#1f2b45"]), hoverinfo="skip",
    ))
    fig.add_annotation(text=f"<b>{'n/a' if rate is None else f'{rate:.0f}%'}</b>", showarrow=False,
                       font=dict(size=34, color=score_color(rate)))
    fig.update_layout(**_LAYOUT, showlegend=False)
    return fig


def severity_chart(summary: Summary) -> go.Figure:
    sev = SEVERITY_ORDER
    fig = go.Figure(go.Bar(
        x=sev, y=[summary.severity[s].failed for s in sev],
        marker_color=[SEVERITY_COLORS[s] for s in sev],
        text=[summary.severity[s].failed for s in sev], textposition="outside", cliponaxis=False,
        hovertemplate="%{x}: %{y} failed<extra></extra>",
    ))
    fig.update_layout(**_LAYOUT, yaxis=dict(title="Failed findings", gridcolor="#1f2b45", zeroline=False),
                      xaxis=dict(title=None))
    return fig


def service_chart(summary: Summary) -> go.Figure:
    names = list(summary.service)
    fig = go.Figure()
    fig.add_bar(name="Passed", y=names, x=[summary.service[n].passed for n in names], orientation="h",
                marker_color=COLORS["pass"])
    fig.add_bar(name="Failed", y=names, x=[summary.service[n].failed for n in names], orientation="h",
                marker_color=COLORS["fail"])
    fig.update_layout(**_LAYOUT, barmode="stack", legend=dict(orientation="h", y=1.15, x=0, traceorder="normal"),
                      xaxis=dict(gridcolor="#1f2b45", title="Findings"), yaxis=dict(autorange="reversed"))
    return fig
