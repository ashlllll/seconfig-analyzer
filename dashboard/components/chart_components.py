"""
SecConfig Analyzer — Modern Plotly Chart Factory (v2.0)
  - Ghost-track background on category bars (sorted descending)
  - Severity donut pulls critical/high segments + smart center label
  - Per-node coloured markers on NIST radar + reference ring
  - Consistent _rgba() glow fills across all charts
  - Unified _title() annotation helper
"""

from __future__ import annotations

from typing import Dict, List, Tuple
import numpy as np
import plotly.graph_objects as go

# ── Design Tokens ─────────────────────────────────────────────────────────────
_BG       = "#06090d"
_BG_PANEL = "#0c1118"
_BG_CARD  = "#0f1923"
_BORDER   = "#1e2d3d"
_GRID     = "#131e28"
_TEXT     = "#d0e4f7"
_MUTED    = "#5a7a96"

_RED    = "#f05252"
_ORANGE = "#f0923a"
_YELLOW = "#f0c040"
_GREEN  = "#2ecc71"
_BLUE   = "#4090f5"
_CYAN   = "#22ddd4"
_PURPLE = "#9b7bf5"

_SEV_COLOURS = {
    "critical": _RED,
    "high":     _ORANGE,
    "medium":   _YELLOW,
    "low":      _GREEN,
    "info":     _BLUE,
}
_CAT_COLOURS = {
    "credentials":    _RED,
    "encryption":     _CYAN,
    "access_control": _ORANGE,
    "logging":        _BLUE,
    "baseline":       _PURPLE,
}
_NIST_COLOURS = {
    "IDENTIFY": _CYAN,
    "PROTECT":  _BLUE,
    "DETECT":   _RED,
    "RESPOND":  _ORANGE,
    "RECOVER":  _GREEN,
}


def _rgba(hex_col: str, alpha: float = 0.18) -> str:
    """Convert hex colour + alpha to rgba() string."""
    h = hex_col.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"rgba({r},{g},{b},{alpha})"


def _base_layout(height: int = 380) -> dict:
    """Shared dark-terminal layout defaults for all charts."""
    return dict(
        height=height,
        paper_bgcolor=_BG_CARD,
        plot_bgcolor=_BG_CARD,
        font=dict(family="'JetBrains Mono', 'DM Mono', monospace", color=_TEXT, size=11),
        margin=dict(l=48, r=24, t=52, b=44),
        legend=dict(
            bgcolor="rgba(12,17,24,0.80)",
            bordercolor=_BORDER,
            borderwidth=1,
            font=dict(size=10, color=_TEXT),
        ),
        xaxis=dict(
            gridcolor=_GRID, linecolor=_BORDER, zeroline=False,
            tickfont=dict(color=_MUTED, size=10),
            title=dict(font=dict(color=_MUTED, size=11), standoff=10),
        ),
        yaxis=dict(
            gridcolor=_GRID, linecolor=_BORDER, zeroline=False,
            tickfont=dict(color=_MUTED, size=10),
            title=dict(font=dict(color=_MUTED, size=11), standoff=10),
        ),
        hoverlabel=dict(
            bgcolor=_BG_PANEL, bordercolor=_BORDER,
            font=dict(family="'JetBrains Mono', monospace", size=11, color=_TEXT),
        ),
        transition=dict(duration=280, easing="cubic-in-out"),
    )


def _title(text: str, sub: str = "") -> dict:
    """Styled chart title as a Plotly annotation dict."""
    label = f"<b>{text}</b>"
    if sub:
        label += f"<br><span style='color:{_MUTED};font-size:9px'>{sub}</span>"
    return dict(
        text=label, x=0.0, y=1.08,
        xref="paper", yref="paper",
        showarrow=False, xanchor="left", yanchor="bottom",
        font=dict(size=12, color=_TEXT),
    )


# ── 1. Severity Donut ─────────────────────────────────────────────────────────

def severity_donut(counts: dict, height: int = 320) -> go.Figure:
    """
    Donut chart for severity distribution.
    Critical/High segments are pulled outward for visual emphasis.
    Centre label shows critical count (or total if no criticals).
    """
    order  = ["critical", "high", "medium", "low", "info"]
    labels = [k for k in order if counts.get(k, 0) > 0]
    values = [counts[k] for k in labels]
    cols   = [_SEV_COLOURS[k] for k in labels]
    pulls  = [0.05 if k in ("critical", "high") else 0.0 for k in labels]
    total  = sum(values)
    crit   = counts.get("critical", 0)

    fig = go.Figure(go.Pie(
        labels=[l.upper() for l in labels],
        values=values,
        hole=0.65,
        pull=pulls,
        marker=dict(colors=cols, line=dict(color=_BG_CARD, width=3)),
        textinfo="label+percent",
        textfont=dict(size=9, color=_TEXT),
        hovertemplate="<b>%{label}</b><br>%{value} issues (%{percent})<extra></extra>",
        direction="clockwise",
        sort=False,
    ))

    center = (
        f"<b style='font-size:20px;color:{_RED}'>{crit}</b>"
        f"<br><span style='font-size:9px;color:{_MUTED}'>CRITICAL</span>"
    ) if crit else (
        f"<b style='font-size:22px;color:{_GREEN}'>{total}</b>"
        f"<br><span style='font-size:9px;color:{_MUTED}'>ISSUES</span>"
    )

    fig.add_annotation(
        text=center, x=0.5, y=0.5,
        showarrow=False, xanchor="center", yanchor="middle",
    )

    layout = _base_layout(height)
    layout.update(
        showlegend=True,
        legend=dict(**layout["legend"], orientation="v", x=1.02, y=0.5),
        annotations=[_title("Severity Distribution", f"Total: {total} issues")],
        margin=dict(l=20, r=100, t=56, b=20),
    )
    layout.pop("xaxis", None)
    layout.pop("yaxis", None)
    fig.update_layout(**layout)
    return fig


# ── 2. Category Bar Chart ─────────────────────────────────────────────────────

def category_bar(counts: dict, height: int = 320) -> go.Figure:
    """
    Horizontal bar chart sorted descending.
    Each bar has a ghost full-width track behind it for visual context.
    """
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    cats   = [k for k, _ in sorted_items]
    vals   = [v for _, v in sorted_items]
    cols   = [_CAT_COLOURS.get(c, _BLUE) for c in cats]
    pretty = [c.replace("_", " ").upper() for c in cats]
    max_v  = max(vals) if vals else 1

    fig = go.Figure()

    # Ghost background track
    fig.add_trace(go.Bar(
        y=pretty, x=[max_v * 1.06] * len(cats), orientation="h",
        marker=dict(color=[_rgba(c, 0.09) for c in cols], line=dict(width=0)),
        showlegend=False, hoverinfo="skip",
    ))

    # Real bars
    fig.add_trace(go.Bar(
        y=pretty, x=vals, orientation="h",
        marker=dict(
            color=cols,
            line=dict(color=[_rgba(c, 0.70) for c in cols], width=1),
            opacity=0.88,
        ),
        text=[f"  {v}" for v in vals],
        textposition="inside",
        textfont=dict(size=11, color=_BG),
        hovertemplate="<b>%{y}</b><br>%{x} issues<extra></extra>",
        name="Issues",
    ))

    layout = _base_layout(height)
    layout.update(
        barmode="overlay",
        annotations=[_title("Issues by Category")],
        xaxis=dict(**layout["xaxis"],
                   title=dict(text="Count", font=dict(color=_MUTED))),
        yaxis=dict(**layout["yaxis"], tickfont=dict(color=_TEXT, size=10)),
        showlegend=False,
        bargap=0.28,
    )
    fig.update_layout(**layout)
    return fig


# ── 3. Monte Carlo Histogram ──────────────────────────────────────────────────

def mc_histogram(
    before: List[float],
    after:  List[float],
    before_mean: float,
    after_mean:  float,
    height: int = 380,
) -> go.Figure:
    """
    Overlapping histograms (before=red, after=green) with:
    - Dashed mean lines
    - Risk-reduction badge (top-right)

    BUGFIX: annotations list was broken in v1.0 (had dead `if False` branch).
    """
    reduction = ((before_mean - after_mean) / before_mean * 100) if before_mean > 0 else 0.0
    badge_col = _GREEN if reduction >= 0 else _ORANGE

    fig = go.Figure()

    fig.add_trace(go.Histogram(
        x=list(before), name="Before Remediation", nbinsx=60,
        marker=dict(color=_RED, opacity=0.45,
                    line=dict(color=_rgba(_RED, 0.55), width=0.5)),
        hovertemplate="Risk %{x:.1f} — Count %{y}<extra>Before</extra>",
    ))

    fig.add_trace(go.Histogram(
        x=list(after), name="After Remediation", nbinsx=60,
        marker=dict(color=_GREEN, opacity=0.50,
                    line=dict(color=_rgba(_GREEN, 0.55), width=0.5)),
        hovertemplate="Risk %{x:.1f} — Count %{y}<extra>After</extra>",
    ))

    for val, col, label, pos in [
        (before_mean, _RED,   f"μ before = {before_mean:.1f}", "top right"),
        (after_mean,  _GREEN, f"μ after  = {after_mean:.1f}",  "top left"),
    ]:
        fig.add_vline(
            x=val, line_dash="dot", line_color=col, line_width=1.8,
            annotation_text=label,
            annotation_font=dict(color=col, size=9),
            annotation_position=pos,
        )

    layout = _base_layout(height)
    layout.update(
        barmode="overlay",
        annotations=[
            _title("Risk Distribution — Monte Carlo", "10,000 iterations"),
            dict(
                text=f"▼ {abs(reduction):.1f}% risk reduction",
                x=0.99, y=0.97, xref="paper", yref="paper",
                showarrow=False, xanchor="right",
                font=dict(size=10, color=badge_col),
                bgcolor=_rgba(badge_col, 0.12),
                bordercolor=badge_col, borderwidth=1, borderpad=5,
            ),
        ],
        xaxis=dict(**layout["xaxis"],
                   title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)),
                   range=[0, 105]),
        yaxis=dict(**layout["yaxis"],
                   title=dict(text="Frequency", font=dict(color=_MUTED))),
        legend=dict(**layout["legend"], x=0.70, y=0.95),
    )
    fig.update_layout(**layout)
    return fig


# ── 4. Adaptive Wave Comparison ───────────────────────────────────────────────

def _adaptive_density_wave(
    samples: List[float],
    x_min: float = 0.0,
    x_max: float = 100.0,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    KDE-style smooth density wave.

    BUGFIX: np.trapz instead of np.trapezoid (NumPy <2.0 safe).
    IMPROVED: 11-tap Gaussian-shaped smoothing kernel (vs 7-tap in v1.0).
    """
    x_dense = np.linspace(x_min, x_max, 800)
    arr = np.asarray(samples, dtype=float)
    arr = arr[np.isfinite(arr)]

    if arr.size == 0:
        return x_dense, np.zeros_like(x_dense)

    arr = np.clip(arr, x_min, x_max)

    # Degenerate: all values identical
    if arr.size < 3 or np.allclose(arr, arr[0]):
        sigma = max((x_max - x_min) / 60.0, 1.5)
        y = np.exp(-0.5 * ((x_dense - float(arr.mean())) / sigma) ** 2)
        y_sum = np.trapz(y, x_dense)   # ← BUGFIX: was np.trapezoid
        return x_dense, (y / y_sum) if y_sum > 0 else y

    bins = int(np.clip(np.sqrt(arr.size) * 2.8, 32, 140))
    counts_h, edges = np.histogram(arr, bins=bins, range=(x_min, x_max), density=True)
    centers = (edges[:-1] + edges[1:]) / 2.0

    # 11-tap Gaussian-shaped kernel (wider than v1.0's 7-tap)
    k = np.array([1, 2, 4, 6, 8, 9, 8, 6, 4, 2, 1], dtype=float)
    k /= k.sum()
    smooth = np.clip(np.convolve(counts_h, k, mode="same"), 0.0, None)

    return x_dense, np.interp(x_dense, centers, smooth, left=0.0, right=0.0)


def mc_wave_comparison(
    before: List[float],
    after:  List[float],
    before_mean: float,
    after_mean:  float,
    height: int = 380,
) -> go.Figure:
    """
    Adaptive density wave comparison with:
    - P5–P95 confidence interval shading behind each wave
    - Glow fill under each curve
    - Mean dashed lines
    - Risk-reduction badge (top-right)
    """
    bx, by = _adaptive_density_wave(before)
    ax, ay = _adaptive_density_wave(after)
    top = max(float(np.max(by)), float(np.max(ay)), 0.001)

    reduction = ((before_mean - after_mean) / before_mean * 100) if before_mean > 0 else 0.0
    badge_col = _GREEN if reduction >= 0 else _ORANGE

    b_lo = float(np.percentile(before, 5))
    b_hi = float(np.percentile(before, 95))
    a_lo = float(np.percentile(after,  5))
    a_hi = float(np.percentile(after,  95))

    fig = go.Figure()

    # P5-P95 confidence bands (drawn first, behind waves)
    for lo, hi, col in [(b_lo, b_hi, _RED), (a_lo, a_hi, _GREEN)]:
        band_x = np.linspace(lo, hi, 300)
        band_y = np.full(300, top * 0.10)
        fig.add_trace(go.Scatter(
            x=np.concatenate([band_x, band_x[::-1]]),
            y=np.concatenate([band_y, np.zeros(300)]),
            fill="toself",
            fillcolor=_rgba(col, 0.08),
            line=dict(color="rgba(0,0,0,0)"),
            showlegend=False, hoverinfo="skip",
        ))

    # Before wave
    fig.add_trace(go.Scatter(
        x=bx, y=by, mode="lines", name="Before Remediation",
        line=dict(color=_RED, width=2.8, shape="spline", smoothing=1.2),
        fill="tozeroy", fillcolor=_rgba(_RED, 0.20),
        hovertemplate="Risk: %{x:.1f}  Density: %{y:.5f}<extra>Before</extra>",
    ))

    # After wave
    fig.add_trace(go.Scatter(
        x=ax, y=ay, mode="lines", name="After Remediation",
        line=dict(color=_GREEN, width=2.8, shape="spline", smoothing=1.2),
        fill="tozeroy", fillcolor=_rgba(_GREEN, 0.22),
        hovertemplate="Risk: %{x:.1f}  Density: %{y:.5f}<extra>After</extra>",
    ))

    # Mean dashed lines
    for val, col, label, pos in [
        (before_mean, _RED,   f"μ={before_mean:.1f}", "top right"),
        (after_mean,  _GREEN, f"μ={after_mean:.1f}",  "top left"),
    ]:
        fig.add_vline(
            x=float(np.clip(val, 0, 100)),
            line_dash="dot", line_color=col, line_width=1.6,
            annotation_text=label,
            annotation_font=dict(color=col, size=9),
            annotation_position=pos,
        )

    layout = _base_layout(height)
    layout.update(
        annotations=[
            _title("Risk Density Waves", "Shaded band = P5–P95 confidence interval"),
            dict(
                text=f"▼ {abs(reduction):.1f}% reduction",
                x=0.99, y=0.97, xref="paper", yref="paper",
                showarrow=False, xanchor="right",
                font=dict(size=10, color=badge_col),
                bgcolor=_rgba(badge_col, 0.12),
                bordercolor=badge_col, borderwidth=1, borderpad=5,
            ),
        ],
        xaxis=dict(**layout["xaxis"],
                   title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)),
                   range=[0, 100], dtick=10),
        yaxis=dict(**layout["yaxis"],
                   title=dict(text="Density", font=dict(color=_MUTED)),
                   rangemode="tozero", showticklabels=False),
        hovermode="x unified",
        legend=dict(**layout["legend"], x=0.68, y=0.92),
    )
    fig.update_layout(**layout)
    return fig


# ── 5. Box / Violin Hybrid ────────────────────────────────────────────────────

def risk_box_plot(
    before: List[float],
    after:  List[float],
    height: int = 360,
) -> go.Figure:
    """
    Violin + box hybrid — richer distribution insight than a plain box plot.
    Shows shape, outliers, median, and mean line simultaneously.
    """
    fig = go.Figure()

    for data, col, label in [
        (list(before), _RED,   "Before"),
        (list(after),  _GREEN, "After"),
    ]:
        fig.add_trace(go.Violin(
            y=data, name=label,
            box_visible=True,
            meanline_visible=True,
            fillcolor=_rgba(col, 0.20),
            line_color=col,
            marker=dict(color=col, opacity=0.35, size=3),
            meanline=dict(color=col, width=2),
            points="outliers",
            pointpos=-1.6,
            hovertemplate=f"<b>{label}</b><br>%{{y:.2f}}<extra></extra>",
            width=0.55,
        ))

    layout = _base_layout(height)
    layout.update(
        annotations=[_title("Risk Distribution Comparison", "Violin + box overlay")],
        yaxis=dict(**layout["yaxis"],
                   title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)),
                   range=[0, 108]),
        violingap=0.30,
    )
    fig.update_layout(**layout)
    return fig


# ── 6. NIST Radar Chart ───────────────────────────────────────────────────────

def nist_radar(counts: dict, height: int = 340) -> go.Figure:
    """
    NIST CSF radar chart.

    BUGFIX: safe max() when all counts are zero (v1.0 would produce range=[0,1]
    but dtick logic was fragile; now explicitly guarded).
    ADDED: dotted outer reference ring, per-node coloured markers, clockwise rotation.
    """
    functions = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
    values    = [counts.get(f, 0) for f in functions]

    # BUGFIX: safe max
    max_val = max(values) if any(v > 0 for v in values) else 1
    r_max   = max_val + max(1, int(max_val * 0.25))
    cols    = [_NIST_COLOURS[f] for f in functions]

    fig = go.Figure()

    # Outer reference ring
    fig.add_trace(go.Scatterpolar(
        r=[r_max] * (len(functions) + 1),
        theta=functions + [functions[0]],
        mode="lines",
        line=dict(color=_BORDER, width=1, dash="dot"),
        showlegend=False, hoverinfo="skip",
    ))

    # Data polygon
    fig.add_trace(go.Scatterpolar(
        r=values + [values[0]],
        theta=functions + [functions[0]],
        fill="toself",
        fillcolor=_rgba(_BLUE, 0.18),
        line=dict(color=_BLUE, width=2.2),
        marker=dict(
            color=cols + [cols[0]],
            size=10,
            line=dict(color=_BG_CARD, width=2),
        ),
        name="Detected Issues",
        hovertemplate="<b>%{theta}</b><br>%{r} issues<extra></extra>",
    ))

    layout = _base_layout(height)
    layout.update(
        polar=dict(
            bgcolor=_BG_CARD,
            radialaxis=dict(
                visible=True,
                gridcolor=_BORDER, linecolor=_BORDER,
                tickfont=dict(color=_MUTED, size=8),
                range=[0, r_max],
                tickmode="linear",
                dtick=max(1, r_max // 4),
            ),
            angularaxis=dict(
                gridcolor=_BORDER, linecolor=_BORDER,
                tickfont=dict(color=_TEXT, size=10),
                direction="clockwise",
                rotation=90,
            ),
        ),
        annotations=[_title("NIST CSF Coverage", "Issues mapped per function")],
        showlegend=False,
    )
    layout.pop("xaxis", None)
    layout.pop("yaxis", None)
    fig.update_layout(**layout)
    return fig


# ── 7. Risk Gauge ─────────────────────────────────────────────────────────────

def risk_gauge(
    value: float,
    label: str = "Risk Score",
    height: int = 240,
) -> go.Figure:
    """
    Gauge with four zone colours, severity label overlay, and delta vs 50.
    Delta turns green when improving (moving away from 50 toward 0).
    """
    if value < 20:
        col, level = _GREEN,  "LOW"
    elif value < 40:
        col, level = _YELLOW, "MEDIUM"
    elif value < 70:
        col, level = _ORANGE, "HIGH"
    else:
        col, level = _RED,    "CRITICAL"

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=round(value, 1),
        title=dict(
            text=(
                f"<b style='color:{_MUTED}'>{label}</b><br>"
                f"<span style='font-size:10px;color:{col}'>{level}</span>"
            ),
            font=dict(size=11),
        ),
        number=dict(font=dict(size=30, color=col, family="JetBrains Mono, monospace")),
        delta=dict(
            reference=50,
            increasing=dict(color=_RED),
            decreasing=dict(color=_GREEN),
        ),
        gauge=dict(
            axis=dict(
                range=[0, 100], tickwidth=1, tickcolor=_BORDER,
                tickfont=dict(color=_MUTED, size=8), nticks=6,
            ),
            bar=dict(color=col, thickness=0.22,
                     line=dict(color=_rgba(col, 0.45), width=2)),
            bgcolor=_BG_PANEL,
            borderwidth=1, bordercolor=_BORDER,
            steps=[
                dict(range=[0,  20],  color=_rgba(_GREEN,  0.10)),
                dict(range=[20, 40],  color=_rgba(_YELLOW, 0.09)),
                dict(range=[40, 70],  color=_rgba(_ORANGE, 0.09)),
                dict(range=[70, 100], color=_rgba(_RED,    0.09)),
            ],
            threshold=dict(
                line=dict(color=col, width=2.5),
                thickness=0.82,
                value=value,
            ),
        ),
    ))

    layout = _base_layout(height)
    layout.update(margin=dict(l=20, r=20, t=60, b=20))
    layout.pop("xaxis", None)
    layout.pop("yaxis", None)
    fig.update_layout(**layout)
    return fig


# ── 8. Risk Reduction Bar ─────────────────────────────────────────────────────

def risk_reduction_bar(
    before_mean: float,
    after_mean:  float,
    height: int = 200,
) -> go.Figure:
    """
    Horizontal before/after comparison with delta annotation.
    Bars use glow-fill style (transparent fill + coloured border).
    """
    reduction = ((before_mean - after_mean) / before_mean * 100) if before_mean > 0 else 0.0
    x_max = max(before_mean, after_mean) * 1.35

    fig = go.Figure()

    for label, val, col in [
        ("BEFORE", before_mean, _RED),
        ("AFTER",  after_mean,  _GREEN),
    ]:
        fig.add_trace(go.Bar(
            y=[label], x=[val], orientation="h",
            marker=dict(
                color=_rgba(col, 0.14),
                line=dict(color=col, width=2),
            ),
            text=f"  {val:.1f}",
            textposition="inside",
            textfont=dict(color=col, size=13, family="JetBrains Mono, monospace"),
            hovertemplate=f"<b>{label}</b>: %{{x:.2f}}<extra></extra>",
            showlegend=False,
        ))

    layout = _base_layout(height)
    layout.update(
        annotations=[
            _title("Mean Risk Score"),
            dict(
                text=f"▼ {reduction:.1f}% reduction",
                x=max(before_mean, after_mean) * 1.03, y=0.5,
                xref="x", yref="paper",
                showarrow=False, xanchor="left",
                font=dict(size=11, color=_GREEN),
            ),
        ],
        xaxis=dict(**layout["xaxis"],
                   title=dict(text="Risk Score", font=dict(color=_MUTED)),
                   range=[0, x_max]),
        yaxis=dict(**layout["yaxis"], tickfont=dict(color=_TEXT, size=11)),
        bargap=0.35, showlegend=False,
        margin=dict(l=70, r=40, t=52, b=30),
    )
    fig.update_layout(**layout)
    return fig


# ── 9. NEW: Risk Timeline ─────────────────────────────────────────────────────

def risk_timeline(
    labels: List[str],
    scores: List[float],
    height: int = 320,
) -> go.Figure:
    """
    Line chart tracking risk score across multiple remediation checkpoints.

    Args:
        labels: Checkpoint names e.g. ["Raw Config", "Fix Creds", "Fix Crypto", "Final"]
        scores: Risk score (0–100) at each checkpoint

    Each marker is colour-coded by severity zone:
        >= 70 → red (critical), >= 40 → orange (high),
        >= 20 → yellow (medium), < 20 → green (low)
    """
    marker_cols = [
        _RED    if s >= 70 else
        _ORANGE if s >= 40 else
        _YELLOW if s >= 20 else
        _GREEN
        for s in scores
    ]

    fig = go.Figure()

    # Soft background area fill
    fig.add_trace(go.Scatter(
        x=labels, y=scores, mode="lines",
        line=dict(color=_BLUE, width=0.5),
        fill="tozeroy", fillcolor=_rgba(_BLUE, 0.07),
        showlegend=False, hoverinfo="skip",
    ))

    # Main line with coloured markers
    fig.add_trace(go.Scatter(
        x=labels, y=scores,
        mode="lines+markers+text",
        name="Risk Score",
        line=dict(color=_BLUE, width=2.4, shape="spline", smoothing=0.8),
        marker=dict(
            color=marker_cols, size=13,
            line=dict(color=_BG_CARD, width=2),
        ),
        text=[f"{s:.1f}" for s in scores],
        textposition="top center",
        textfont=dict(size=9, color=_TEXT),
        hovertemplate="<b>%{x}</b><br>Risk: %{y:.1f}<extra></extra>",
    ))

    # Severity zone backgrounds
    fig.add_hrect(y0=70, y1=100, fillcolor=_rgba(_RED,    0.05), line_width=0)
    fig.add_hrect(y0=40, y1=70,  fillcolor=_rgba(_ORANGE, 0.04), line_width=0)
    fig.add_hrect(y0=0,  y1=20,  fillcolor=_rgba(_GREEN,  0.05), line_width=0)

    layout = _base_layout(height)
    layout.update(
        annotations=[_title("Risk Score Timeline", "Across remediation checkpoints")],
        yaxis=dict(**layout["yaxis"],
                   title=dict(text="Risk Score", font=dict(color=_MUTED)),
                   range=[0, 110]),
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


# ── 10. NEW: Issue Heatmap ────────────────────────────────────────────────────

def issue_heatmap(
    matrix: Dict[str, Dict[str, int]],
    height: int = 320,
) -> go.Figure:
    """
    Category × Severity heatmap — shows where risk concentrates at a glance.

    Args:
        matrix: {category: {severity: count}}
                e.g. {"credentials": {"critical": 2, "high": 1, "medium": 0, ...}}

    Colourscale: dark panel → teal → orange → red (matches severity palette).
    """
    categories = ["credentials", "encryption", "access_control", "logging", "baseline"]
    severities  = ["critical", "high", "medium", "low", "info"]

    z = np.array([
        [matrix.get(cat, {}).get(sev, 0) for sev in severities]
        for cat in categories
    ], dtype=float)

    colorscale = [
        [0.00, _BG_PANEL],
        [0.25, _rgba(_CYAN,   0.80)],
        [0.60, _ORANGE],
        [1.00, _RED],
    ]

    fig = go.Figure(go.Heatmap(
        z=z,
        x=[s.upper() for s in severities],
        y=[c.replace("_", " ").upper() for c in categories],
        colorscale=colorscale,
        showscale=True,
        colorbar=dict(
            title=dict(text="Count", font=dict(color=_MUTED, size=10)),
            tickfont=dict(color=_MUTED, size=9),
            bgcolor=_BG_CARD,
            bordercolor=_BORDER, borderwidth=1,
            thickness=12, len=0.80,
        ),
        text=[[str(int(v)) if v > 0 else "" for v in row] for row in z],
        texttemplate="%{text}",
        textfont=dict(size=12, color=_TEXT),
        hovertemplate="<b>%{y}</b> × <b>%{x}</b><br>Count: %{z}<extra></extra>",
        xgap=4, ygap=4,
    ))

    layout = _base_layout(height)
    layout.update(
        annotations=[_title("Issue Heatmap", "Category × Severity")],
        xaxis=dict(**layout["xaxis"],
                   title=dict(text="Severity", font=dict(color=_MUTED))),
        yaxis=dict(**layout["yaxis"],
                   tickfont=dict(color=_TEXT, size=10)),
        margin=dict(l=115, r=65, t=56, b=44),
    )
    fig.update_layout(**layout)
    return fig