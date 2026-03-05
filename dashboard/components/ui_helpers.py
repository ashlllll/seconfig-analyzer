"""
components/ui_helpers.py
~~~~~~~~~~~~~~~~~~~~~~~~
Reusable UI helper functions for SecConfig Analyzer dashboard.
Provides consistent styling via HTML/CSS injection.
"""

import streamlit as st
from pathlib import Path


# ---------------------------------------------------------------------------
# CSS Loader
# ---------------------------------------------------------------------------

def load_css() -> None:
    """Inject custom CSS into the Streamlit app."""
    css_path = Path(__file__).parent.parent / "styles" / "custom.css"
    if css_path.exists():
        with open(css_path) as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Severity badge
# ---------------------------------------------------------------------------

SEVERITY_COLOURS = {
    "critical": ("#f04f47", "rgba(240,79,71,0.15)", "rgba(240,79,71,0.35)"),
    "high":     ("#e88c3a", "rgba(232,140,58,0.15)", "rgba(232,140,58,0.35)"),
    "medium":   ("#d9a83a", "rgba(217,168,58,0.15)", "rgba(217,168,58,0.35)"),
    "low":      ("#3dba6e", "rgba(61,186,110,0.15)", "rgba(61,186,110,0.35)"),
    "info":     ("#3b8ef3", "rgba(59,142,243,0.15)", "rgba(59,142,243,0.35)"),
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
    "info":     "🔵",
}

NIST_ICONS = {
    "IDENTIFY": "🔍",
    "PROTECT":  "🛡️",
    "DETECT":   "📡",
    "RESPOND":  "⚡",
    "RECOVER":  "🔄",
}


def severity_badge(severity: str) -> str:
    """Return an HTML severity badge string."""
    sev = severity.lower()
    colour, bg, border = SEVERITY_COLOURS.get(sev, ("#6b8299", "rgba(107,130,153,0.15)", "rgba(107,130,153,0.35)"))
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:10px;font-weight:600;font-family:\'JetBrains Mono\',monospace;'
        f'text-transform:uppercase;letter-spacing:0.06em;'
        f'color:{colour};background:{bg};border:1px solid {border};">'
        f'{sev}</span>'
    )


def category_badge(category: str) -> str:
    """Return an HTML category badge string."""
    cat_colours = {
        "credentials":    ("#f04f47", "rgba(240,79,71,0.1)"),
        "encryption":     ("#26d4d4", "rgba(38,212,212,0.1)"),
        "access_control": ("#e88c3a", "rgba(232,140,58,0.1)"),
        "logging":        ("#3dba6e", "rgba(61,186,110,0.1)"),
        "baseline":       ("#3b8ef3", "rgba(59,142,243,0.1)"),
    }
    colour, bg = cat_colours.get(category.lower(), ("#6b8299", "rgba(107,130,153,0.1)"))
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:4px;'
        f'font-size:10px;font-weight:500;font-family:\'JetBrains Mono\',monospace;'
        f'color:{colour};background:{bg};">'
        f'{category.replace("_", " ").title()}</span>'
    )


# ---------------------------------------------------------------------------
# Section header
# ---------------------------------------------------------------------------

def section_header(title: str, subtitle: str = "", icon: str = "") -> None:
    """Render a styled section header."""
    icon_html = f'<span style="font-size:1.4rem;margin-right:10px;">{icon}</span>' if icon else ""
    sub_html = (
        f'<p style="color:#6b8299;font-size:13px;margin-top:4px;margin-bottom:0;">{subtitle}</p>'
        if subtitle else ""
    )
    st.markdown(
        f"""
        <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
            <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                       color:#c9d8e8;margin:0;display:flex;align-items:center;">
                {icon_html}{title}
            </h1>
            {sub_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Metric row
# ---------------------------------------------------------------------------

def metric_card(label: str, value: str, delta: str = "", delta_colour: str = "normal") -> None:
    """Render a single styled metric card via st.metric."""
    st.metric(label=label, value=value, delta=delta if delta else None)


# ---------------------------------------------------------------------------
# Issue card
# ---------------------------------------------------------------------------

def issue_card(issue: dict, index: int = 0) -> None:
    """
    Render an expandable issue card.

    issue dict keys: title, severity, category, rule_id, line_number,
                     description, vulnerable_code, remediation_hint,
                     nist_function, cwe_id
    """
    sev   = issue.get("severity", "info")
    title = issue.get("title", "Unknown Issue")
    icon  = SEVERITY_ICONS.get(sev.lower(), "⚪")
    rule  = issue.get("rule_id", "")
    line  = issue.get("line_number", "?")

    label = f"{icon} [{rule}] {title}  —  Line {line}"

    with st.expander(label, expanded=False):
        col1, col2, col3 = st.columns([2, 2, 2])
        with col1:
            st.markdown(
                f"**Severity:** {severity_badge(sev)}",
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(
                f"**Category:** {category_badge(issue.get('category', ''))}",
                unsafe_allow_html=True,
            )
        with col3:
            nist = issue.get("nist_function", "")
            cwe  = issue.get("cwe_id", "")
            nist_icon = NIST_ICONS.get(nist.upper(), "")
            st.markdown(
                f"**NIST:** {nist_icon} {nist} &nbsp;|&nbsp; **CWE:** {cwe}",
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.markdown(f"**Description:** {issue.get('description', '')}")

        vuln_code = issue.get("vulnerable_code", "")
        if vuln_code:
            st.markdown(f"**Vulnerable Code** (line {line}):")
            st.code(vuln_code, language="bash")

        hint = issue.get("remediation_hint", "")
        if hint:
            st.info(f"💡 **Remediation:** {hint}")


# ---------------------------------------------------------------------------
# Fix card
# ---------------------------------------------------------------------------

def fix_card(fix: dict) -> bool:
    """
    Render a fix card with code diff.
    Returns True if the user selected this fix via checkbox.
    """
    issue_title = fix.get("issue_title", "Unknown")
    fix_type    = fix.get("fix_type", "manual")
    priority    = fix.get("priority", "medium")

    type_colour = {
        "automated":      ("#3dba6e", "🤖"),
        "semi_automated": ("#d9a83a", "🔧"),
        "manual":         ("#6b8299", "📋"),
    }.get(fix_type, ("#6b8299", "📋"))

    colour, type_icon = type_colour
    label = f"{type_icon} {issue_title}"

    with st.expander(label, expanded=False):
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(
                f'<span style="color:{colour};font-family:\'JetBrains Mono\',monospace;'
                f'font-size:12px;">⬤ {fix_type.replace("_", " ").upper()}</span>',
                unsafe_allow_html=True,
            )
        with col2:
            st.markdown(f"**Priority:** `{priority}`")
        with col3:
            effort = fix.get("effort", "medium")
            st.markdown(f"**Effort:** `{effort}`")

        st.markdown("---")

        original = fix.get("original_code", "")
        fixed    = fix.get("fixed_code", "")

        if original or fixed:
            left, right = st.columns(2)
            with left:
                st.markdown("🔴 **Before (vulnerable)**")
                st.code(original or "(none)", language="bash")
            with right:
                st.markdown("🟢 **After (fixed)**")
                st.code(fixed or "(manual fix required)", language="bash")

        explanation = fix.get("explanation", "")
        if explanation:
            st.markdown(f"**Explanation:** {explanation}")

        side_effects = fix.get("side_effects", [])
        if side_effects:
            st.warning("⚠️ **Side effects:** " + " · ".join(side_effects))

        # Checkbox for selecting this fix
        selected = st.checkbox(
            "Apply this fix",
            key=f"fix_{fix.get('fix_id', id(fix))}",
        )
        return selected

    return False


# ---------------------------------------------------------------------------
# Empty state
# ---------------------------------------------------------------------------

def empty_state(message: str, icon: str = "📂", hint: str = "") -> None:
    """Render a centred empty-state message."""
    hint_html = (
        f'<p style="color:#3d5166;font-size:13px;margin-top:8px;">{hint}</p>'
        if hint else ""
    )
    st.markdown(
        f"""
        <div style="text-align:center;padding:60px 20px;color:#6b8299;">
            <div style="font-size:3rem;margin-bottom:12px;">{icon}</div>
            <p style="font-size:15px;margin:0;">{message}</p>
            {hint_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Risk score colour
# ---------------------------------------------------------------------------

def risk_colour(score: float) -> str:
    """Return a hex colour based on risk score (0–100)."""
    if score >= 80:
        return "#f04f47"
    elif score >= 60:
        return "#e88c3a"
    elif score >= 40:
        return "#d9a83a"
    elif score >= 20:
        return "#3dba6e"
    else:
        return "#3b8ef3"


def risk_label(score: float) -> str:
    """Return a text label for a risk score."""
    if score >= 80:   return "CRITICAL"
    elif score >= 60: return "HIGH"
    elif score >= 40: return "MEDIUM"
    elif score >= 20: return "LOW"
    else:             return "MINIMAL"


# ---------------------------------------------------------------------------
# Sidebar branding
# ---------------------------------------------------------------------------

def render_sidebar_brand() -> None:
    """Render the logo/branding block in the sidebar."""
    st.sidebar.markdown(
        """
        <div style="padding:20px 14px 16px;border-bottom:1px solid #1a2838;margin-bottom:12px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.1rem;
                        font-weight:700;color:#c9d8e8;letter-spacing:-0.02em;">
                🔒 SecConfig
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                        color:#3d5166;margin-top:2px;letter-spacing:0.05em;">
                ANALYZER v1.0
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
