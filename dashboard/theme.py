"""Design tokens and global CSS - a restrained dark security-console palette."""

STATUS_COLORS = {"PASS": "#2fbf71", "FAIL": "#ff4d6a", "ERROR": "#b48cff", "N/A": "#6b7488", "NOT RUN": "#3d465a"}
SEVERITY_COLORS = {"CRITICAL": "#ff4d6a", "HIGH": "#ff8a3d", "MEDIUM": "#f5c542", "LOW": "#5aa9ff"}
GRADE_COLORS = {"Healthy": "#2fbf71", "Needs attention": "#f5a623", "Poor": "#ff4d6a", "Not scored": "#6b7488"}
MUTED = "#8b95a8"
TEXT = "#e6e9ef"
BORDER = "#232c3f"
PANEL = "#121826"
BG = "#0b0f17"
ACCENT = "#4f8cff"

CSS = f"""
<style>
:root {{
  --bg:{BG}; --panel:{PANEL}; --panel2:#0f1522; --border:{BORDER}; --text:{TEXT}; --muted:{MUTED}; --accent:{ACCENT};
  --pass:{STATUS_COLORS['PASS']}; --fail:{STATUS_COLORS['FAIL']}; --err:{STATUS_COLORS['ERROR']}; --na:{STATUS_COLORS['N/A']};
  --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
}}
/* ---- chrome: hide Streamlit furniture ---- */
#MainMenu, footer, [data-testid="stToolbar"], [data-testid="stDecoration"], [data-testid="stStatusWidget"] {{display:none !important;}}
header[data-testid="stHeader"] {{background:transparent; height:2.2rem;}}
.block-container {{padding:2.4rem 2.2rem 3rem; max-width:1480px;}}
html, body, [class*="st-"] {{font-feature-settings:"tnum";}}
h1,h2,h3,h4 {{letter-spacing:-.01em; color:var(--text);}}

/* ---- sidebar ---- */
section[data-testid="stSidebar"] [data-testid="stButtonGroup"] [role="radiogroup"] {{flex-wrap:nowrap; width:100%;}}
section[data-testid="stSidebar"] [data-testid="stButtonGroup"] button[role="radio"] {{flex:1 1 auto; padding:0 .25rem; white-space:nowrap; justify-content:center; overflow:visible;}}
section[data-testid="stSidebar"] [data-testid="stButtonGroup"] button[role="radio"] p {{font-size:.78rem; overflow:visible; text-overflow:clip;}}
section[data-testid="stSidebar"] {{background:#0d121d; border-right:1px solid var(--border);}}
section[data-testid="stSidebar"] .block-container {{padding-top:1.4rem;}}
.cp-brand {{font-size:1.15rem; font-weight:700; letter-spacing:-.01em;}}
.cp-brand b {{color:var(--accent);}}
.cp-brand-sub {{color:var(--muted); font-size:.74rem; margin-bottom:1rem;}}
.cp-safe {{border:1px solid #2fbf7155; background:#2fbf7112; border-radius:4px; padding:.65rem .75rem; margin:.4rem 0 1rem;}}
.cp-safe b {{color:var(--pass); font-size:.78rem; letter-spacing:.06em; text-transform:uppercase;}}
.cp-safe p {{margin:.25rem 0 0; font-size:.8rem; color:#c9d1e0; line-height:1.4;}}

/* ---- header ---- */
.cp-top {{display:flex; justify-content:space-between; align-items:flex-start; gap:1rem; flex-wrap:wrap;
          padding-bottom:1rem; border-bottom:1px solid var(--border);}}
.cp-title {{font-size:1.65rem; font-weight:750; line-height:1.1; margin:0;}}
.cp-title b {{color:var(--accent);}}
.cp-tag {{color:var(--muted); font-size:.85rem; margin-top:.25rem;}}
.cp-meta {{display:flex; gap:1.6rem; flex-wrap:wrap; margin-top:.9rem;}}
.cp-meta div {{min-width:0;}}
.cp-meta .k {{font-size:.66rem; letter-spacing:.09em; text-transform:uppercase; color:var(--muted);}}
.cp-meta .v {{font-family:var(--mono); font-size:.86rem; color:var(--text); margin-top:.1rem; overflow-wrap:anywhere;}}
.cp-mode {{display:inline-flex; align-items:center; gap:.5rem; padding:.35rem .8rem; border-radius:4px; font-weight:700;
           font-size:.8rem; letter-spacing:.08em; border:1px solid;}}
.cp-mode i {{width:8px; height:8px; border-radius:50%; background:currentColor; display:inline-block;}}
.cp-mode.demo {{color:#f5a623; border-color:#f5a62366; background:#f5a62314;}}
.cp-mode.live {{color:var(--pass); border-color:#2fbf7166; background:#2fbf7114;}}
.cp-ro {{display:inline-block; margin-left:.5rem; padding:.35rem .7rem; border-radius:4px; font-size:.72rem; font-weight:600;
         letter-spacing:.06em; color:var(--accent); border:1px solid #4f8cff55; background:#4f8cff12; vertical-align:top;}}
.cp-banner {{margin-top:.9rem; padding:.55rem .8rem; border-radius:4px; font-size:.84rem; border:1px solid #f5a62355;
             background:#f5a62310; color:#f1d9a8;}}
.cp-banner.warn {{border-color:#b48cff66; background:#b48cff12; color:#d9c8ff;}}

/* ---- hero ---- */
.cp-hero {{display:grid; grid-template-columns:minmax(250px,330px) 1fr; gap:1rem; margin-top:1.1rem;}}
@media (max-width:900px) {{.cp-hero {{grid-template-columns:1fr;}}}}
.cp-panel {{background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:1.1rem 1.25rem;}}
.cp-panel.list {{padding-top:.3rem; padding-bottom:.3rem;}}
div[data-testid="stHtml"] {{margin:0;}}
.cp-label {{font-size:.68rem; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); font-weight:600;}}
.cp-score {{font-size:4.2rem; font-weight:800; line-height:1; margin:.35rem 0 .2rem; letter-spacing:-.03em;}}
.cp-score small {{font-size:1.6rem; font-weight:700; margin-left:.1rem;}}
.cp-grade {{display:inline-block; padding:.18rem .6rem; border-radius:3px; font-weight:700; font-size:.78rem;
            letter-spacing:.05em; text-transform:uppercase; border:1px solid;}}
.cp-sub {{color:var(--muted); font-size:.8rem; margin-top:.55rem; line-height:1.5;}}
.cp-sub b {{color:var(--text); font-weight:600;}}
.cp-seg {{display:flex; height:14px; border-radius:3px; overflow:hidden; background:#1a2234; margin:.7rem 0 1rem;}}
.cp-seg > span {{display:block; height:100%;}}
.cp-counts {{display:grid; grid-template-columns:repeat(4,1fr); gap:.7rem;}}
@media (max-width:700px) {{.cp-counts {{grid-template-columns:repeat(2,1fr);}}}}
.cp-count {{border-top:3px solid; padding-top:.5rem;}}
.cp-count .n {{font-size:2rem; font-weight:750; line-height:1.1;}}
.cp-count .l {{font-size:.72rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); font-weight:600;}}
.cp-count .h {{font-size:.72rem; color:var(--muted); margin-top:.1rem;}}
.cp-checks {{margin-top:1.1rem; padding-top:.8rem; border-top:1px solid var(--border); display:flex; gap:2rem; flex-wrap:wrap;
             font-size:.82rem; color:var(--muted);}}
.cp-checks b {{color:var(--text); font-size:1rem; margin-right:.25rem;}}

/* ---- severity strip ---- */
.cp-strip {{display:grid; grid-template-columns:repeat(6,1fr); gap:.7rem; margin-top:.9rem;}}
@media (max-width:1100px) {{.cp-strip {{grid-template-columns:repeat(3,1fr);}}}}
@media (max-width:600px) {{.cp-strip {{grid-template-columns:repeat(2,1fr);}}}}
.cp-kpi {{background:var(--panel); border:1px solid var(--border); border-left:4px solid; border-radius:4px; padding:.7rem .9rem;}}
.cp-kpi .n {{font-size:1.8rem; font-weight:750; line-height:1.1;}}
.cp-kpi .l {{font-size:.7rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); font-weight:600;}}
.cp-kpi .h {{font-size:.72rem; color:var(--muted);}}

/* ---- section headings ---- */
.cp-h {{font-size:.95rem; font-weight:700; margin:1.3rem 0 0; display:flex; align-items:baseline; gap:.6rem;}}
.cp-h span {{font-size:.78rem; color:var(--muted); font-weight:400;}}

/* ---- lists / badges ---- */
.cp-badge {{display:inline-block; min-width:4.6rem; text-align:center; padding:.12rem .5rem; border-radius:3px; font-size:.68rem;
            font-weight:750; letter-spacing:.06em; color:#0b0f17; text-transform:uppercase;}}
.cp-badge.ghost {{background:transparent !important; border:1px solid; min-width:0;}}
.cp-mono {{font-family:var(--mono); font-size:.8rem;}}
.cp-row {{display:flex; gap:.8rem; align-items:center; padding:.6rem 0; border-bottom:1px solid var(--border);}}
.cp-row:last-child {{border-bottom:0;}}
.cp-row .t {{font-size:.88rem; line-height:1.3;}}
.cp-row .s {{font-size:.75rem; color:var(--muted); margin-top:.1rem; overflow-wrap:anywhere;}}
.cp-fwrow {{margin-bottom:.85rem;}}
.cp-fwrow .top {{display:flex; justify-content:space-between; font-size:.86rem; margin-bottom:.3rem;}}
.cp-fwrow .bar {{height:8px; background:#1a2234; border-radius:2px; overflow:hidden;}}
.cp-fwrow .bar > div {{height:100%;}}
.cp-fwrow .m {{font-size:.72rem; color:var(--muted); margin-top:.25rem;}}
.cp-approx {{color:#f5c542; font-size:.68rem; font-weight:600; letter-spacing:.04em; border:1px solid #f5c54255; background:#f5c54210;
             padding:.05rem .4rem; border-radius:3px; margin-left:.4rem; white-space:nowrap;}}
.cp-exact {{color:var(--pass); font-size:.68rem; font-weight:600; letter-spacing:.04em; border:1px solid #2fbf7155; background:#2fbf7110;
            padding:.05rem .4rem; border-radius:3px; margin-left:.4rem; white-space:nowrap;}}
.cp-notice {{border:1px solid #f5c54244; background:#f5c54210; border-radius:4px; padding:.6rem .85rem; font-size:.83rem; color:#eadfb8;
             margin:.4rem 0 1rem; line-height:1.45;}}

/* ---- framework / service cards ---- */
.cp-grid4 {{display:grid; grid-template-columns:repeat(4,1fr); gap:.8rem;}}
@media (max-width:1200px) {{.cp-grid4 {{grid-template-columns:repeat(2,1fr);}}}}
@media (max-width:640px) {{.cp-grid4 {{grid-template-columns:1fr;}}}}
.cp-card {{background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:1rem 1.1rem;}}
.cp-card .name {{font-weight:700; font-size:.95rem;}}
.cp-card .ver {{font-size:.72rem; color:var(--muted); margin-bottom:.5rem;}}
.cp-card .rate {{font-size:2.4rem; font-weight:800; line-height:1.1; margin:.4rem 0 .5rem;}}
.cp-stats {{display:grid; grid-template-columns:1fr 1fr; gap:.45rem .8rem; margin-top:.8rem; font-size:.78rem;}}
.cp-stats div span {{display:block; font-size:.66rem; letter-spacing:.07em; text-transform:uppercase; color:var(--muted);}}
.cp-stats div b {{font-size:1.05rem;}}
.cp-legend {{display:flex; gap:.9rem; flex-wrap:wrap; font-size:.72rem; color:var(--muted); margin-top:.35rem;}}
.cp-legend i {{display:inline-block; width:8px; height:8px; border-radius:2px; margin-right:.3rem;}}

/* ---- finding detail ---- */
.cp-detail {{background:var(--panel); border:1px solid var(--border); border-radius:6px; padding:1.2rem 1.4rem;}}
.cp-detail.fail {{border-left:4px solid var(--fail);}}
.cp-detail.pass {{border-left:4px solid var(--pass);}}
.cp-detail.error {{border-left:4px solid var(--err);}}
.cp-detail.na {{border-left:4px solid var(--na);}}
.cp-detail h3 {{margin:.5rem 0 .9rem; font-size:1.25rem; line-height:1.3;}}
.cp-detail h4 {{margin:1.2rem 0 .4rem; font-size:.7rem; letter-spacing:.1em; text-transform:uppercase; color:var(--muted); font-weight:700;}}
.cp-detail p {{margin:0; font-size:.92rem; line-height:1.55; color:#cfd6e4;}}
.cp-detail ol {{margin:0; padding-left:1.25rem; font-size:.92rem; line-height:1.6; color:#cfd6e4;}}
.cp-kv {{display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:.8rem;}}
@media (max-width:800px) {{.cp-kv {{grid-template-columns:repeat(2,1fr);}}}}
.cp-kv .k {{font-size:.66rem; letter-spacing:.09em; text-transform:uppercase; color:var(--muted);}}
.cp-kv .v {{font-family:var(--mono); font-size:.84rem; overflow-wrap:anywhere; margin-top:.1rem;}}
.cp-cmp {{display:grid; grid-template-columns:1fr 1fr; gap:.8rem; margin-top:1.1rem;}}
@media (max-width:800px) {{.cp-cmp {{grid-template-columns:1fr;}}}}
.cp-cmp > div {{background:var(--panel2); border:1px solid var(--border); border-radius:4px; padding:.7rem .9rem; font-size:.88rem; line-height:1.45;}}
.cp-cmp .k {{font-size:.66rem; letter-spacing:.09em; text-transform:uppercase; font-weight:700; margin-bottom:.25rem;}}
.cp-cmp .cur.fail {{border-color:#ff4d6a66;}} .cp-cmp .cur.fail .k {{color:var(--fail);}}
.cp-cmp .cur.pass {{border-color:#2fbf7155;}} .cp-cmp .cur.pass .k {{color:var(--pass);}}
.cp-cmp .cur.error .k {{color:var(--err);}} .cp-cmp .cur.na .k {{color:var(--na);}}
.cp-cmp .exp .k {{color:var(--muted);}}
table.cp-map {{width:100%; border-collapse:collapse; font-size:.84rem; margin-top:.2rem;}}
table.cp-map th {{text-align:left; font-size:.66rem; letter-spacing:.08em; text-transform:uppercase; color:var(--muted); padding:.35rem .5rem; border-bottom:1px solid var(--border);}}
table.cp-map td {{padding:.5rem; border-bottom:1px solid var(--border); vertical-align:top; color:#cfd6e4;}}
table.cp-map tr:last-child td {{border-bottom:0;}}

/* ---- streamlit widget polish ---- */
div[data-testid="stTabs"] [data-baseweb="tab-list"] {{gap:.2rem; border-bottom:1px solid var(--border); margin-top:1.1rem;}}
div[data-testid="stTabs"] button[data-baseweb="tab"] {{height:2.8rem; padding:0 1.1rem; font-weight:600;}}
div[data-testid="stTabs"] button[data-baseweb="tab"] p {{font-size:.92rem;}}
div[data-testid="stDownloadButton"] button, div[data-testid="stButton"] button {{border-radius:4px; font-weight:600;}}
div[data-testid="stDataFrame"] {{border:1px solid var(--border); border-radius:4px;}}
label[data-testid="stWidgetLabel"] p {{font-size:.74rem; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); font-weight:600;}}
.stAlert {{border-radius:4px;}}
</style>
"""


def score_color(rate: float | None) -> str:
    if rate is None:
        return STATUS_COLORS["N/A"]
    return "#2fbf71" if rate >= 85 else "#f5a623" if rate >= 60 else "#ff4d6a"
