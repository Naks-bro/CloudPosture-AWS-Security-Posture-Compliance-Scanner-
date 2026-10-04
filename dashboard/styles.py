"""Theme tokens and CSS for the dashboard."""

COLORS = {
    "pass": "#22c55e",
    "fail": "#ef4444",
    "error": "#f59e0b",
    "na": "#64748b",
    "muted": "#94a3b8",
    "panel": "#111a2e",
    "border": "#1f2b45",
    "accent": "#38bdf8",
}
SEVERITY_COLORS = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#38bdf8"}

CSS = """
<style>
  .block-container {padding-top: 3.5rem; max-width: 1400px;}
  h1, h2, h3 {letter-spacing: -0.01em;}
  .cp-header {display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:.5rem;
              border-bottom:1px solid #1f2b45; padding-bottom:.9rem; margin-bottom:1.1rem;}
  .cp-title {font-size:1.7rem; font-weight:700; margin:0;}
  .cp-title span {color:#38bdf8;}
  .cp-sub {color:#94a3b8; font-size:.85rem; margin-top:.15rem;}
  .cp-badge {display:inline-block; padding:.18rem .6rem; border-radius:999px; font-size:.72rem; font-weight:700;
             letter-spacing:.06em; border:1px solid;}
  .cp-badge.demo {color:#f59e0b; border-color:#f59e0b55; background:#f59e0b14;}
  .cp-badge.live {color:#22c55e; border-color:#22c55e55; background:#22c55e14;}
  .cp-badge.ro {color:#38bdf8; border-color:#38bdf855; background:#38bdf814; margin-left:.4rem;}
  .cp-card {background:#111a2e; border:1px solid #1f2b45; border-radius:12px; padding:1rem 1.15rem; height:100%;}
  .cp-card .label {color:#94a3b8; font-size:.74rem; text-transform:uppercase; letter-spacing:.08em;}
  .cp-card .value {font-size:2.1rem; font-weight:700; line-height:1.15; margin-top:.2rem;}
  .cp-card .hint {color:#94a3b8; font-size:.78rem; margin-top:.15rem;}
  .cp-section {font-size:1.05rem; font-weight:600; margin:1.6rem 0 .6rem; padding-left:.6rem; border-left:3px solid #38bdf8;}
  .cp-fw {margin-bottom:.9rem;}
  .cp-fw .row {display:flex; justify-content:space-between; font-size:.9rem;}
  .cp-fw .bar {height:8px; background:#1f2b45; border-radius:6px; overflow:hidden; margin:.3rem 0 .15rem;}
  .cp-fw .bar > div {height:100%; border-radius:6px;}
  .cp-fw .meta {color:#94a3b8; font-size:.74rem;}
  .cp-pill {display:inline-block; padding:.05rem .5rem; border-radius:6px; font-size:.7rem; font-weight:700; color:#0b1220;}
  div[data-testid="stExpander"] {border:1px solid #1f2b45; border-radius:10px; background:#0f1729;}
</style>
"""


def score_color(rate: float | None) -> str:
    if rate is None:
        return COLORS["na"]
    return COLORS["pass"] if rate >= 80 else "#eab308" if rate >= 50 else COLORS["fail"]
