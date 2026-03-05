"""
components/chart_components.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Plotly chart helpers for SecConfig Analyzer dashboard.
All charts use the dark terminal colour palette.
"""

from __future__ import annotations
import plotly.graph_objects as go
import plotly.express as px
from typing import Any

# ── Shared theme ──────────────────────────────────────────────────────────────
_BG        = "#06090d"
_PAPER     = "#0c1118"
_GRID      = "#1a2838"
_TEXT      = "#6b8299"
_FONT_MONO = "JetBrains Mono"

_LAYOUT_BASE = dict(
    font=dict(family=_FONT_MONO, color=_TEXT, size=11),
    paper_bgcolor=_PAPER,
    plot_bgcolor=_BG,
    margin=dict(l=40, r=20, t=40, b=40),
    showlegend=True,
    legend=dict(
        bgcolor="rgba(0,0,0,0)",
        bordercolor=_GRID,
        borderwidth=1,
        font=dict(size=11),
    ),
)

SEV_COLOURS = {
    "critical": "#f04f47",
    "high":     "#e88c3a",
    "medium":   "#d9a83a",
    "low":      "#3dba6e",
    "info":     "#3b8ef3",
}


# ── Severity pie / donut ──────────────────────────────────────────────────────

def severity_donut(severity_counts: dict[str, int], height: int = 300) -> go.Figure:
    """Donut chart for severity distribution."""
    labels = [k.capitalize() for k in severity_counts.keys()]
    values = list(severity_counts.values())
    colours = [SEV_COLOURS.get(k.lower(), "#6b8299") for k in severity_counts.keys()]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.6,
        marker=dict(colors=colours, line=dict(color=_BG, width=2)),
        textinfo="label+percent",
        textfont=dict(family=_FONT_MONO, size=11),
        hovertemplate="<b>%{label}</b><br>Count: %{value}<br>%{percent}<extra></extra>",
    ))

    total = sum(values)
    fig.add_annotation(
        text=f"<b>{total}</b><br><span style='font-size:10px'>issues</span>",
        x=0.5, y=0.5,
        font=dict(family=_FONT_MONO, size=16, color="#c9d8e8"),
        showarrow=False,
        align="center",
    )

    fig.update_layout(
        **_LAYOUT_BASE,
        height=height,
        title=dict(text="Severity Distribution", font=dict(size=13, color="#c9d8e8"), x=0.02),
        showlegend=True,
    )
    return fig


# ── Category bar chart ────────────────────────────────────────────────────────

def category_bar(category_counts: dict[str, int], height: int = 280) -> go.Figure:
    """Horizontal bar chart for issue categories."""
    cats   = list(category_counts.keys())
    counts = list(category_counts.values())

    cat_colours = {
        "credentials":    "#f04f47",
        "encryption":     "#26d4d4",
        "access_control": "#e88c3a",
        "logging":        "#3dba6e",
        "baseline":       "#3b8ef3",
    }
    colours = [cat_colours.get(c.lower(), "#6b8299") for c in cats]

    fig = go.Figure(go.Bar(
        x=counts,
        y=[c.replace("_", " ").title() for c in cats],
        orientation="h",
        marker=dict(
            color=colours,
            opacity=0.85,
            line=dict(color=colours, width=0),
        ),
        text=counts,
        textposition="outside",
        textfont=dict(family=_FONT_MONO, size=11, color="#c9d8e8"),
        hovertemplate="<b>%{y}</b>: %{x} issues<extra></extra>",
    ))

    fig.update_layout(
        **_LAYOUT_BASE,
        height=height,
        title=dict(text="Issues by Category", font=dict(size=13, color="#c9d8e8"), x=0.02),
        xaxis=dict(gridcolor=_GRID, zeroline=False, showgrid=True),
        yaxis=dict(gridcolor="rgba(0,0,0,0)", zeroline=False),
        showlegend=False,
        bargap=0.3,
    )
    return fig


# ── Monte Carlo histogram ─────────────────────────────────────────────────────

def mc_histogram(
    before: list[float],
    after: list[float],
    before_mean: float,
    after_mean: float,
    height: int = 380,
) -> go.Figure:
    """Overlapping histograms comparing before/after risk distributions."""
    fig = go.Figure()

    # Before
    fig.add_trace(go.Histogram(
        x=before,
        name="Before remediation",
        nbinsx=60,
        marker=dict(color="rgba(240,79,71,0.5)", line=dict(color="rgba(240,79,71,0.8)", width=0.5)),
        opacity=0.75,
        hovertemplate="Risk: %{x:.1f}<br>Count: %{y}<extra>Before</extra>",
    ))

    # After
    fig.add_trace(go.Histogram(
        x=after,
        name="After remediation",
        nbinsx=60,
        marker=dict(color="rgba(61,186,110,0.5)", line=dict(color="rgba(61,186,110,0.8)", width=0.5)),
        opacity=0.75,
        hovertemplate="Risk: %{x:.1f}<br>Count: %{y}<extra>After</extra>",
    ))

    # Mean lines
    for mean_val, colour, label in [
        (before_mean, "#f04f47", f"Before μ = {before_mean:.1f}"),
        (after_mean,  "#3dba6e", f"After μ = {after_mean:.1f}"),
    ]:
        fig.add_vline(
            x=mean_val, line_dash="dash", line_color=colour, line_width=1.5,
            annotation=dict(
                text=label,
                font=dict(family=_FONT_MONO, size=10, color=colour),
                bgcolor="rgba(0,0,0,0.6)",
            ),
        )

    fig.update_layout(
        **_LAYOUT_BASE,
        height=height,
        barmode="overlay",
        title=dict(text="Risk Distribution: Before vs After Remediation",
                   font=dict(size=13, color="#c9d8e8"), x=0.02),
        xaxis=dict(title="Risk Score (0–100)", gridcolor=_GRID, zeroline=False),
        yaxis=dict(title="Frequency", gridcolor=_GRID, zeroline=False),
    )
    return fig


# ── Box plot comparison ───────────────────────────────────────────────────────

def risk_box_plot(
    before: list[float],
    after: list[float],
    height: int = 320,
) -> go.Figure:
    """Side-by-side box plots for before/after risk."""
    fig = go.Figure()

    for data, name, colour in [
        (before, "Before", "#f04f47"),
        (after,  "After",  "#3dba6e"),
    ]:
        fig.add_trace(go.Box(
            y=data,
            name=name,
            marker=dict(color=colour, size=4, opacity=0.6),
            line=dict(color=colour, width=1.5),
            fillcolor=colour.replace("#", "rgba(").rstrip(")") + ",0.12)",
            boxmean="sd",
            hovertemplate="<b>%{fullData.name}</b><br>Value: %{y:.2f}<extra></extra>",
        ))

    fig.update_layout(
        **_LAYOUT_BASE,
        height=height,
        title=dict(text="Risk Score Distribution", font=dict(size=13, color="#c9d8e8"), x=0.02),
        yaxis=dict(title="Risk Score", gridcolor=_GRID, zeroline=False),
        xaxis=dict(gridcolor="rgba(0,0,0,0)"),
        showlegend=False,
    )
    return fig


# ── NIST Coverage radar ───────────────────────────────────────────────────────

def nist_radar(nist_counts: dict[str, int], height: int = 320) -> go.Figure:
    """Radar/spider chart for NIST CSF function coverage."""
    categories = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    values     = [nist_counts.get(c, 0) for c in categories]
    values_closed = values + [values[0]]
    cats_closed   = categories + [categories[0]]

    fig = go.Figure(go.Scatterpolar(
        r=values_closed,
        theta=cats_closed,
        fill="toself",
        fillcolor="rgba(59,142,243,0.15)",
        line=dict(color="#3b8ef3", width=2),
        marker=dict(color="#3b8ef3", size=6),
        hovertemplate="<b>%{theta}</b><br>Issues: %{r}<extra></extra>",
    ))

    fig.update_layout(
        **_LAYOUT_BASE,
        height=height,
        title=dict(text="NIST CSF Coverage", font=dict(size=13, color="#c9d8e8"), x=0.02),
        polar=dict(
            bgcolor=_BG,
            radialaxis=dict(
                visible=True, gridcolor=_GRID, linecolor=_GRID,
                tickfont=dict(family=_FONT_MONO, size=10, color=_TEXT),
            ),
            angularaxis=dict(
                gridcolor=_GRID, linecolor=_GRID,
                tickfont=dict(family=_FONT_MONO, size=11, color="#c9d8e8"),
            ),
        ),
        showlegend=False,
    )
    return fig


# ── Risk reduction gauge ──────────────────────────────────────────────────────

def risk_gauge(score: float, label: str = "Risk Score", height: int = 250) -> go.Figure:
    """Gauge chart for a single risk score (0–100)."""
    if score >= 80:   colour = "#f04f47"
    elif score >= 60: colour = "#e88c3a"
    elif score >= 40: colour = "#d9a83a"
    elif score >= 20: colour = "#3dba6e"
    else:             colour = "#3b8ef3"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number=dict(
            font=dict(family=_FONT_MONO, size=32, color=colour),
            suffix="",
        ),
        gauge=dict(
            axis=dict(range=[0, 100], tickfont=dict(family=_FONT_MONO, size=10, color=_TEXT)),
            bar=dict(color=colour, thickness=0.25),
            bgcolor=_BG,
            borderwidth=1,
            bordercolor=_GRID,
            steps=[
                dict(range=[0, 20],   color="rgba(59,142,243,0.1)"),
                dict(range=[20, 40],  color="rgba(61,186,110,0.1)"),
                dict(range=[40, 60],  color="rgba(217,168,58,0.1)"),
                dict(range=[60, 80],  color="rgba(232,140,58,0.1)"),
                dict(range=[80, 100], color="rgba(240,79,71,0.1)"),
            ],
        ),
        title=dict(text=label, font=dict(family=_FONT_MONO, size=12, color=_TEXT)),
    ))

    fig.update_layout(**_LAYOUT_BASE, height=height, showlegend=False)
    return fig
