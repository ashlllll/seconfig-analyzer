"""
dashboard/components/chart_components.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Plotly chart factories for the SecConfig Analyzer dashboard.

All functions return go.Figure objects ready for st.plotly_chart().
Colour palette matches the dark terminal theme in custom.css.
"""
from __future__ import annotations

from typing import List, Optional
import numpy as np
import plotly.graph_objects as go
import plotly.express as px

# ── Palette (matches custom.css variables) ────────────────────────────────────
_BG        = "#06090d"
_BG_PANEL  = "#0c1118"
_BG_CARD   = "#101820"
_BORDER    = "#1a2838"
_TEXT      = "#c9d8e8"
_MUTED     = "#6b8299"

_RED    = "#f04f47"
_ORANGE = "#e88c3a"
_YELLOW = "#d9a83a"
_GREEN  = "#3dba6e"
_BLUE   = "#3b8ef3"
_CYAN   = "#26d4d4"

_SEV_COLOURS = {
    "critical": _RED,
    "high":     _ORANGE,
    "medium":   _YELLOW,
    "low":      _GREEN,
    "info":     _BLUE,
}

_CAT_COLOURS = {
    "credentials":    _RED,
    "encryption":     _ORANGE,
    "access_control": _YELLOW,
    "logging":        _BLUE,
    "baseline":       _CYAN,
}

_NIST_COLOURS = {
    "IDENTIFY": _CYAN,
    "PROTECT":  _BLUE,
    "DETECT":   _YELLOW,
    "RESPOND":  _ORANGE,
    "RECOVER":  _GREEN,
}


def _base_layout(height: int = 360) -> dict:
    """Shared layout defaults for all charts."""
    return dict(
        height=height,
        paper_bgcolor=_BG_CARD,
        plot_bgcolor=_BG_CARD,
        font=dict(family="DM Sans, sans-serif", color=_TEXT, size=12),
        margin=dict(l=40, r=20, t=36, b=40),
        legend=dict(
            bgcolor="rgba(0,0,0,0)",
            bordercolor=_BORDER,
            font=dict(size=11),
        ),
        xaxis=dict(
            gridcolor=_BORDER,
            linecolor=_BORDER,
            tickfont=dict(color=_MUTED, size=10),
            title=dict(font=dict(color=_MUTED)),
        ),
        yaxis=dict(
            gridcolor=_BORDER,
            linecolor=_BORDER,
            tickfont=dict(color=_MUTED, size=10),
            title=dict(font=dict(color=_MUTED)),
        ),
    )


# ── 1. Severity Donut ─────────────────────────────────────────────────────────

def severity_donut(
    counts: dict,          # e.g. {"critical": 3, "high": 2, ...}
    height: int = 300,
) -> go.Figure:
    """
    Donut chart showing issue distribution by severity.

    Args:
        counts: Dict mapping severity → count
        height: Chart height in px

    Returns:
        Plotly Figure
    """
    labels  = [k for k, v in counts.items() if v > 0]
    values  = [counts[k] for k in labels]
    colours = [_SEV_COLOURS.get(k, _MUTED) for k in labels]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        hole=0.60,
        marker=dict(colors=colours, line=dict(color=_BG_CARD, width=2)),
        textinfo="label+value",
        textfont=dict(size=11, color=_TEXT),
        hovertemplate="%{label}: %{value} issues<extra></extra>",
    ))

    total = sum(values)
    fig.add_annotation(
        text=f"<b>{total}</b><br><span style='font-size:10px'>issues</span>",
        x=0.5, y=0.5,
        showarrow=False,
        font=dict(size=14, color=_TEXT),
        xanchor="center", yanchor="middle",
    )

    layout = _base_layout(height)
    layout.update(
        showlegend=True,
        title=dict(text="By Severity", font=dict(size=12, color=_MUTED), x=0.02, y=0.97),
    )
    layout.pop("xaxis", None)
    layout.pop("yaxis", None)
    fig.update_layout(**layout)
    return fig


# ── 2. Category Bar Chart ─────────────────────────────────────────────────────

def category_bar(
    counts: dict,          # e.g. {"credentials": 5, "encryption": 3, ...}
    height: int = 300,
) -> go.Figure:
    """
    Horizontal bar chart showing issue count per category.

    Args:
        counts: Dict mapping category → count
        height: Chart height in px

    Returns:
        Plotly Figure
    """
    cats    = list(counts.keys())
    vals    = [counts[c] for c in cats]
    colours = [_CAT_COLOURS.get(c, _BLUE) for c in cats]

    # Prettify category names
    pretty = [c.replace("_", " ").title() for c in cats]

    fig = go.Figure(go.Bar(
        y=pretty,
        x=vals,
        orientation="h",
        marker=dict(color=colours, line=dict(color=_BG_CARD, width=1)),
        text=vals,
        textposition="outside",
        textfont=dict(size=10, color=_TEXT),
        hovertemplate="%{y}: %{x} issues<extra></extra>",
    ))

    layout = _base_layout(height)
    layout.update(
        title=dict(text="By Category", font=dict(size=12, color=_MUTED), x=0.02, y=0.97),
        xaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="Issues", font=dict(color=_MUTED))),
        yaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="", font=dict(color=_MUTED))),
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


# ── 3. Monte Carlo Histogram ──────────────────────────────────────────────────

def mc_histogram(
    before: List[float],
    after:  List[float],
    before_mean: float,
    after_mean:  float,
    height: int = 360,
) -> go.Figure:
    """
    Overlapping histogram showing risk distributions before and after remediation.

    Args:
        before:      Risk samples before remediation
        after:       Risk samples after remediation
        before_mean: Mean of before distribution (for annotation)
        after_mean:  Mean of after distribution (for annotation)
        height:      Chart height in px

    Returns:
        Plotly Figure
    """
    before_arr = np.array(before, dtype=float)
    after_arr  = np.array(after,  dtype=float)

    fig = go.Figure()

    # Before
    fig.add_trace(go.Histogram(
        x=before_arr,
        name="Before Remediation",
        nbinsx=50,
        marker_color=_RED,
        opacity=0.55,
        hovertemplate="Risk: %{x:.1f}<br>Count: %{y}<extra>Before</extra>",
    ))

    # After
    fig.add_trace(go.Histogram(
        x=after_arr,
        name="After Remediation",
        nbinsx=50,
        marker_color=_GREEN,
        opacity=0.55,
        hovertemplate="Risk: %{x:.1f}<br>Count: %{y}<extra>After</extra>",
    ))

    # Mean lines
    fig.add_vline(
        x=before_mean, line_dash="dash", line_color=_RED, line_width=1.5,
        annotation_text=f"μ={before_mean:.1f}",
        annotation_font=dict(color=_RED, size=10),
        annotation_position="top right",
    )
    fig.add_vline(
        x=after_mean, line_dash="dash", line_color=_GREEN, line_width=1.5,
        annotation_text=f"μ={after_mean:.1f}",
        annotation_font=dict(color=_GREEN, size=10),
        annotation_position="top left",
    )

    layout = _base_layout(height)
    layout.update(
        barmode="overlay",
        title=dict(
            text="Risk Distribution — Before vs After Remediation",
            font=dict(size=12, color=_MUTED), x=0.02, y=0.97,
        ),
        xaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)), range=[0, 105]),
        yaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="Frequency", font=dict(color=_MUTED))),
        legend=dict(**layout["legend"], x=0.75, y=0.95),
    )
    fig.update_layout(**layout)
    return fig


# ── 4. Box Plot Comparison ────────────────────────────────────────────────────

def risk_box_plot(
    before: List[float],
    after:  List[float],
    height: int = 360,
) -> go.Figure:
    """
    Side-by-side box plots for risk distributions.

    Args:
        before: Risk samples before remediation
        after:  Risk samples after remediation
        height: Chart height in px

    Returns:
        Plotly Figure
    """
    fig = go.Figure()

    fig.add_trace(go.Box(
        y=list(before),
        name="Before",
        marker_color=_RED,
        line_color=_RED,
        fillcolor="rgba(240,79,71,0.15)",
        boxmean="sd",
        hovertemplate="Before<br>%{y:.2f}<extra></extra>",
    ))

    fig.add_trace(go.Box(
        y=list(after),
        name="After",
        marker_color=_GREEN,
        line_color=_GREEN,
        fillcolor="rgba(61,186,110,0.15)",
        boxmean="sd",
        hovertemplate="After<br>%{y:.2f}<extra></extra>",
    ))

    layout = _base_layout(height)
    layout.update(
        title=dict(text="Risk Distribution Comparison", font=dict(size=12, color=_MUTED), x=0.02, y=0.97),
        yaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)), range=[0, 105]),
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


# ── 5. NIST Radar Chart ───────────────────────────────────────────────────────

def nist_radar(
    counts: dict,          # {"IDENTIFY": 0, "PROTECT": 5, "DETECT": 3, ...}
    height: int = 320,
) -> go.Figure:
    """
    Radar / spider chart showing NIST CSF function coverage.

    Args:
        counts: Dict mapping NIST function → issue count
        height: Chart height in px

    Returns:
        Plotly Figure
    """
    functions = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    values    = [counts.get(f, 0) for f in functions]
    # Close the polygon
    functions_closed = functions + [functions[0]]
    values_closed    = values + [values[0]]

    colours = [_NIST_COLOURS[f] for f in functions]

    fig = go.Figure(go.Scatterpolar(
        r=values_closed,
        theta=functions_closed,
        fill="toself",
        fillcolor="rgba(59,142,243,0.12)",
        line=dict(color=_BLUE, width=2),
        marker=dict(color=colours + [colours[0]], size=8),
        hovertemplate="%{theta}: %{r} issues<extra></extra>",
    ))

    layout = _base_layout(height)
    layout.update(
        polar=dict(
            bgcolor=_BG_CARD,
            radialaxis=dict(
                visible=True,
                gridcolor=_BORDER,
                linecolor=_BORDER,
                tickfont=dict(color=_MUTED, size=9),
                range=[0, max(values) + 1 if max(values) > 0 else 5],
            ),
            angularaxis=dict(
                gridcolor=_BORDER,
                linecolor=_BORDER,
                tickfont=dict(color=_TEXT, size=10),
            ),
        ),
        showlegend=False,
        title=dict(text="NIST CSF Coverage", font=dict(size=12, color=_MUTED), x=0.02, y=0.97),
    )
    # Radar uses polar, remove cartesian axes
    layout.pop("xaxis", None)
    layout.pop("yaxis", None)
    fig.update_layout(**layout)
    return fig


# ── 6. Risk Gauge ─────────────────────────────────────────────────────────────

def risk_gauge(
    value:  float,
    label:  str = "Risk Score",
    height: int = 220,
) -> go.Figure:
    """
    Gauge indicator for a single risk score (0–100).

    Colour zones:
        0–20   → green   (low)
        20–40  → yellow  (medium)
        40–70  → orange  (high)
        70–100 → red     (critical)

    Args:
        value:  The risk score to display (0–100)
        label:  Display label below the gauge
        height: Chart height in px

    Returns:
        Plotly Figure
    """
    # Pick needle colour based on value
    if value < 20:
        colour = _GREEN
    elif value < 40:
        colour = _YELLOW
    elif value < 70:
        colour = _ORANGE
    else:
        colour = _RED

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=round(value, 1),
        title=dict(text=label, font=dict(size=12, color=_MUTED)),
        number=dict(font=dict(size=28, color=colour), suffix=""),
        gauge=dict(
            axis=dict(
                range=[0, 100],
                tickwidth=1,
                tickcolor=_BORDER,
                tickfont=dict(color=_MUTED, size=9),
            ),
            bar=dict(color=colour, thickness=0.25),
            bgcolor=_BG_PANEL,
            borderwidth=1,
            bordercolor=_BORDER,
            steps=[
                dict(range=[0, 20],   color="rgba(61,186,110,0.12)"),
                dict(range=[20, 40],  color="rgba(217,168,58,0.12)"),
                dict(range=[40, 70],  color="rgba(232,140,58,0.12)"),
                dict(range=[70, 100], color="rgba(240,79,71,0.12)"),
            ],
            threshold=dict(
                line=dict(color=colour, width=2),
                thickness=0.75,
                value=value,
            ),
        ),
    ))

    layout = _base_layout(height)
    layout.update(margin=dict(l=20, r=20, t=40, b=20))
    layout.pop("xaxis", None)
    layout.pop("yaxis", None)
    fig.update_layout(**layout)
    return fig


# ── 7. Risk Reduction Bar ─────────────────────────────────────────────────────

def risk_reduction_bar(
    before_mean: float,
    after_mean:  float,
    height: int = 200,
) -> go.Figure:
    """
    Simple horizontal bar showing before vs after risk means.

    Args:
        before_mean: Mean risk before remediation
        after_mean:  Mean risk after remediation
        height:      Chart height in px

    Returns:
        Plotly Figure
    """
    fig = go.Figure()

    fig.add_trace(go.Bar(
        y=["Before", "After"],
        x=[before_mean, after_mean],
        orientation="h",
        marker=dict(color=[_RED, _GREEN]),
        text=[f"{before_mean:.1f}", f"{after_mean:.1f}"],
        textposition="outside",
        textfont=dict(color=_TEXT, size=12),
        hovertemplate="%{y}: %{x:.2f}<extra></extra>",
    ))

    layout = _base_layout(height)
    layout.update(
        title=dict(text="Mean Risk Score", font=dict(size=12, color=_MUTED), x=0.02, y=0.97),
        xaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="Risk Score", font=dict(color=_MUTED)), range=[0, 110]),
        yaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED, size=10),
                   title=dict(text="", font=dict(color=_MUTED))),
        showlegend=False,
        margin=dict(l=60, r=40, t=40, b=30),
    )
    fig.update_layout(**layout)
    return fig