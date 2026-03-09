"""
dashboard/components/chart_adapter.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Compatibility layer for chart rendering.

It calls user-defined functions in chart_components first; if any function
raises at runtime, it falls back to a stable local implementation so
interfaces continue to work without changing chart_components.py.
"""
from __future__ import annotations

from typing import Callable, List

import numpy as np
import plotly.graph_objects as go

from . import chart_components as cc

_BG_CARD = "#101820"
_BORDER = "#1a2838"
_TEXT = "#c9d8e8"
_MUTED = "#6b8299"
_RED = "#f04f47"
_GREEN = "#3dba6e"
_BLUE = "#3b8ef3"
_YELLOW = "#d9a83a"
_ORANGE = "#e88c3a"
_CYAN = "#26d4d4"


def _safe_call(primary: Callable[[], go.Figure], fallback: Callable[[], go.Figure]) -> go.Figure:
    try:
        return primary()
    except Exception:
        return fallback()


def _base_layout(height: int, title: str = "") -> dict:
    return dict(
        height=height,
        paper_bgcolor=_BG_CARD,
        plot_bgcolor=_BG_CARD,
        font=dict(color=_TEXT, size=12, family="DM Sans, sans-serif"),
        margin=dict(l=40, r=20, t=40, b=40),
        title=dict(text=title, x=0.02, y=0.97, font=dict(size=12, color=_MUTED)),
        xaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED)),
        yaxis=dict(gridcolor=_BORDER, linecolor=_BORDER, tickfont=dict(color=_MUTED)),
        legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(color=_TEXT, size=11)),
    )


def severity_donut(counts: dict, height: int = 320) -> go.Figure:
    def _fallback() -> go.Figure:
        labels = [k for k, v in counts.items() if v > 0]
        values = [counts[k] for k in labels]
        colours = {
            "critical": _RED,
            "high": _ORANGE,
            "medium": _YELLOW,
            "low": _GREEN,
            "info": _BLUE,
        }
        fig = go.Figure(go.Pie(
            labels=labels,
            values=values,
            hole=0.58,
            marker=dict(colors=[colours.get(k, _MUTED) for k in labels]),
            textinfo="label+value",
        ))
        layout = _base_layout(height, "By Severity")
        layout.pop("xaxis", None)
        layout.pop("yaxis", None)
        fig.update_layout(**layout)
        return fig

    return _safe_call(lambda: cc.severity_donut(counts, height=height), _fallback)


def category_bar(counts: dict, height: int = 320) -> go.Figure:
    def _fallback() -> go.Figure:
        cats = list(counts.keys())
        vals = [counts[c] for c in cats]
        pretty = [c.replace("_", " ").title() for c in cats]
        fig = go.Figure(go.Bar(
            y=pretty,
            x=vals,
            orientation="h",
            marker=dict(color=[_RED, _ORANGE, _YELLOW, _BLUE, _CYAN][:len(pretty)]),
            text=vals,
            textposition="outside",
        ))
        layout = _base_layout(height, "By Category")
        layout.update(xaxis=dict(**layout["xaxis"], title=dict(text="Count", font=dict(color=_MUTED))))
        fig.update_layout(**layout)
        return fig

    return _safe_call(lambda: cc.category_bar(counts, height=height), _fallback)


def mc_histogram(
    before: List[float],
    after: List[float],
    before_mean: float,
    after_mean: float,
    height: int = 360,
) -> go.Figure:
    def _fallback() -> go.Figure:
        b = np.asarray(before, dtype=float)
        a = np.asarray(after, dtype=float)
        fig = go.Figure()
        fig.add_trace(go.Histogram(
            x=b,
            name="Before Remediation",
            marker_color=_RED,
            opacity=0.55,
            nbinsx=50,
        ))
        fig.add_trace(go.Histogram(
            x=a,
            name="After Remediation",
            marker_color=_GREEN,
            opacity=0.55,
            nbinsx=50,
        ))
        fig.add_vline(x=before_mean, line_dash="dash", line_color=_RED, line_width=1.4)
        fig.add_vline(x=after_mean, line_dash="dash", line_color=_GREEN, line_width=1.4)
        layout = _base_layout(height, "Risk Distribution — Before vs After Remediation")
        layout.update(
            barmode="overlay",
            xaxis=dict(**layout["xaxis"], title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)), range=[0, 105]),
            yaxis=dict(**layout["yaxis"], title=dict(text="Frequency", font=dict(color=_MUTED))),
        )
        fig.update_layout(**layout)
        return fig

    return _safe_call(
        lambda: cc.mc_histogram(before, after, before_mean, after_mean, height=height),
        _fallback,
    )


def risk_box_plot(before: List[float], after: List[float], height: int = 360) -> go.Figure:
    def _fallback() -> go.Figure:
        fig = go.Figure()
        fig.add_trace(go.Box(y=list(before), name="Before", marker_color=_RED, line_color=_RED, boxmean="sd"))
        fig.add_trace(go.Box(y=list(after), name="After", marker_color=_GREEN, line_color=_GREEN, boxmean="sd"))
        layout = _base_layout(height, "Risk Distribution Comparison")
        layout.update(
            yaxis=dict(**layout["yaxis"], title=dict(text="Risk Score (0–100)", font=dict(color=_MUTED)), range=[0, 105]),
            showlegend=False,
        )
        fig.update_layout(**layout)
        return fig

    return _safe_call(lambda: cc.risk_box_plot(before, after, height=height), _fallback)


def nist_radar(counts: dict, height: int = 320) -> go.Figure:
    def _fallback() -> go.Figure:
        keys = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]
        vals = [counts.get(k, 0) for k in keys]
        fig = go.Figure(go.Bar(
            x=keys,
            y=vals,
            marker_color=[_CYAN, _BLUE, _YELLOW, _ORANGE, _GREEN],
        ))
        layout = _base_layout(height, "NIST CSF Coverage")
        layout.update(yaxis=dict(**layout["yaxis"], title=dict(text="Issues", font=dict(color=_MUTED))))
        fig.update_layout(**layout)
        return fig

    return _safe_call(lambda: cc.nist_radar(counts, height=height), _fallback)


def risk_gauge(value: float, label: str = "Risk Score", height: int = 220) -> go.Figure:
    def _fallback() -> go.Figure:
        colour = _GREEN if value < 20 else (_YELLOW if value < 40 else (_ORANGE if value < 70 else _RED))
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=round(float(value), 1),
            number=dict(font=dict(color=colour, size=26)),
            title=dict(text=label, font=dict(color=_MUTED)),
            gauge=dict(
                axis=dict(range=[0, 100], tickfont=dict(color=_MUTED)),
                bar=dict(color=colour),
                bgcolor="#0c1118",
                bordercolor=_BORDER,
                borderwidth=1,
            ),
        ))
        layout = _base_layout(height)
        layout.pop("xaxis", None)
        layout.pop("yaxis", None)
        fig.update_layout(**layout)
        return fig

    return _safe_call(lambda: cc.risk_gauge(value, label=label, height=height), _fallback)
