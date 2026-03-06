"""
dashboard/components/sidebar.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Shared sidebar for ALL SecConfig Analyzer pages.

Usage — add these 2 lines at the top of every page (after set_page_config + CSS):

    from dashboard.components.sidebar import render_sidebar
    render_sidebar(current_page="Upload")

Page name options:
    "Home" | "Upload" | "Red Team" | "Blue Team" |
    "Risk Analysis" | "AI Explainer" | "Reports"
"""

import streamlit as st


# ---------------------------------------------------------------------------
# Navigation definition
# ---------------------------------------------------------------------------

NAV_ITEMS = [
    # ── Workflow group ──────────────────────────────────────────────────
    {"icon": "🏠", "label": "Home",          "page": "app.py",                       "group": "Workflow"},
    {"icon": "📤", "label": "Upload",         "page": "pages/2_📤_Upload.py",         "group": "Workflow"},
    {"icon": "🔴", "label": "Red Team",       "page": "pages/3_🔴_Red_Team.py",       "group": "Workflow"},
    {"icon": "🔵", "label": "Blue Team",      "page": "pages/4_🔵_Blue_Team.py",      "group": "Workflow"},
    {"icon": "📊", "label": "Risk Analysis",  "page": "pages/5_📊_Risk_Analysis.py",  "group": "Workflow"},
    # ── Output group ────────────────────────────────────────────────────
    {"icon": "💬", "label": "AI Explainer",   "page": "pages/6_💬_AI_Explainer.py",   "group": "Output"},
    {"icon": "📋", "label": "Reports",        "page": "pages/7_📋_Reports.py",        "group": "Output"},
]

# Severity colours for session status chips
_SEV_COLOUR = {
    "critical": "#f04f47",
    "high":     "#e88c3a",
    "medium":   "#d9a83a",
    "low":      "#3dba6e",
    "info":     "#3b8ef3",
}

# Extension badge colours
_EXT_COLOUR = {
    "env":  "#3dba6e",
    "yaml": "#3b8ef3",
    "yml":  "#3b8ef3",
    "json": "#d9a83a",
}


# ---------------------------------------------------------------------------
# Tiny helpers
# ---------------------------------------------------------------------------

def _get(obj, key, default=""):
    """Get value from dict or dataclass."""
    return obj.get(key, default) if isinstance(obj, dict) else getattr(obj, key, default)

def _issue_severity(issue) -> str:
    return _get(issue, "severity", "info").lower()


# ---------------------------------------------------------------------------
# CSS — makes nav buttons look like Claude's sidebar links
# ---------------------------------------------------------------------------

_SIDEBAR_CSS = """
<style>
/* Hide Streamlit's auto-generated page nav (we build our own) */
[data-testid="stSidebarNav"] { display: none !important; }

/* ── All nav buttons: strip default styling ────────────────────────────── */
[data-testid="stSidebarUserContent"] .nav-btn > button {
    background: transparent !important;
    border: none !important;
    border-radius: 6px !important;
    color: #c9d8e8 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    font-weight: 400 !important;
    text-align: left !important;
    padding: 7px 12px !important;
    width: 100% !important;
    cursor: pointer !important;
    transition: background 0.15s !important;
    box-shadow: none !important;
    letter-spacing: 0 !important;
}
[data-testid="stSidebarUserContent"] .nav-btn > button:hover {
    background: #141e28 !important;
    color: #c9d8e8 !important;
    border: none !important;
}

/* Active page — blue left border, like Claude */
[data-testid="stSidebarUserContent"] .nav-btn-active > button {
    background: rgba(59,142,243,0.12) !important;
    border-left: 2px solid #3b8ef3 !important;
    border-radius: 0 6px 6px 0 !important;
    color: #3b8ef3 !important;
    font-weight: 600 !important;
    pointer-events: none !important;
}

/* Locked/disabled page — greyed out */
[data-testid="stSidebarUserContent"] .nav-btn-disabled > button {
    color: #3d5166 !important;
    cursor: default !important;
    pointer-events: none !important;
    opacity: 0.45 !important;
}

/* New Analysis button — solid blue, like Claude's "New chat" */
[data-testid="stSidebarUserContent"] .new-analysis-btn > button {
    background: #3b8ef3 !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 6px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
    padding: 8px 14px !important;
    width: 100% !important;
    margin: 6px 0 !important;
    box-shadow: none !important;
    transition: background 0.15s !important;
}
[data-testid="stSidebarUserContent"] .new-analysis-btn > button:hover {
    background: #2a7de0 !important;
}
</style>
"""


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _section_label(text: str) -> None:
    """Small uppercase group label (like Claude's 'Recents', 'Projects' labels)."""
    st.sidebar.markdown(
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:9px;'
        f'color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;'
        f'padding:10px 14px 3px;">{text}</div>',
        unsafe_allow_html=True,
    )


def _divider() -> None:
    st.sidebar.markdown(
        '<hr style="border:none;border-top:1px solid #1a2838;margin:6px 0 2px;">',
        unsafe_allow_html=True,
    )


def _render_logo() -> None:
    """Top logo block — mirrors Claude's 'Claude' wordmark area."""
    st.sidebar.markdown(
        """
        <div style="padding:1px 14px 12px;border-bottom:1px solid #1a2838;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.05rem;
                        font-weight:700;color:#c9d8e8;letter-spacing:-0.02em;">
                🔒 SecConfig
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:9px;
                        color:#3d5166;margin-top:3px;letter-spacing:0.08em;">
                ANALYZER v1.0 &nbsp;·&nbsp; LSBF Singapore
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_new_analysis_button() -> None:
    """
    'New Analysis' button at top — mirrors Claude's '+ New chat'.
    Clears session state and navigates to Upload page.
    """
    st.sidebar.markdown('<div class="new-analysis-btn">', unsafe_allow_html=True)
    if st.sidebar.button("＋  New Analysis", key="sidebar_new_analysis", use_container_width=True):
        # Wipe all analysis state so user starts fresh
        for key in [
            "file_name", "file_type", "raw_content", "config_file",
            "issues", "fixes", "selected_fix_ids", "simulation_result",
            "analysis_ran", "fixes_generated", "simulation_ran", "chat_history",
        ]:
            st.session_state.pop(key, None)
        st.switch_page("pages/2_📤_Upload.py")
    st.sidebar.markdown('</div>', unsafe_allow_html=True)


def _render_file_chip(ss) -> None:
    """Active file indicator below the New Analysis button."""
    if ss.get("file_name"):
        chip_col = _EXT_COLOUR.get(ss.get("file_type", ""), "#6b8299")
        name     = ss["file_name"]
        ft       = ss.get("file_type", "?")
        st.sidebar.markdown(
            f"""
            <div style="display:flex;align-items:center;gap:8px;
                        padding:7px 12px;margin:4px 6px 2px;
                        background:#101820;border:1px solid #1a2838;border-radius:6px;">
                <span style="font-family:'JetBrains Mono',monospace;font-size:8px;
                             color:{chip_col};background:{chip_col}18;
                             border:1px solid {chip_col}44;border-radius:3px;
                             padding:1px 5px;text-transform:uppercase;flex-shrink:0;">
                    .{ft}
                </span>
                <span style="font-family:'JetBrains Mono',monospace;font-size:11px;
                             color:#c9d8e8;white-space:nowrap;overflow:hidden;
                             text-overflow:ellipsis;max-width:148px;"
                      title="{name}">{name}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.sidebar.markdown(
            """
            <div style="padding:7px 12px;margin:4px 6px 2px;
                        background:#0c1118;border:1px dashed #1a2838;border-radius:6px;
                        font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;">
                📂 No file loaded
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_nav(current_page: str, unlocked: dict) -> None:
    """
    Grouped navigation — Workflow / Output.
    Each item is a real Streamlit button (so clicks actually work).
    Active page gets blue highlight, locked pages show a lock icon and are unclickable.
    """
    groups: dict[str, list] = {}
    for item in NAV_ITEMS:
        groups.setdefault(item["group"], []).append(item)

    for group_name, items in groups.items():
        _section_label(group_name)

        for item in items:
            label     = item["label"]
            icon      = item["icon"]
            page      = item["page"]
            is_active = label == current_page
            enabled   = unlocked.get(label, True)

            # Choose CSS class based on state
            if is_active:
                css_class = "nav-btn nav-btn-active"
                btn_label = f"{icon}  {label}"
            elif not enabled:
                css_class = "nav-btn nav-btn-disabled"
                btn_label = f"{icon}  {label}  🔒"
            else:
                css_class = "nav-btn"
                btn_label = f"{icon}  {label}"

            # Wrap button in a div with the appropriate class
            st.sidebar.markdown(f'<div class="{css_class}">', unsafe_allow_html=True)
            clicked = st.sidebar.button(
                btn_label,
                key=f"nav_{label.replace(' ', '_')}",
                use_container_width=True,
            )
            st.sidebar.markdown("</div>", unsafe_allow_html=True)

            # Navigate only when clicked, enabled, and not already on this page
            if clicked and enabled and not is_active:
                st.switch_page(page)


def _render_session_status(ss) -> None:
    """
    Session status — mirrors Claude's 'Recents' list.
    Shows a quick summary of what has been run this session.
    """
    _section_label("Session Status")

    has_analysis   = bool(ss.get("analysis_ran") and ss.get("issues"))
    has_fixes      = bool(ss.get("fixes_generated") and ss.get("fixes"))
    has_simulation = bool(ss.get("simulation_ran") and ss.get("simulation_result"))

    rows: list[tuple[str, str]] = []

    # ── Red Team status ────────────────────────────────────────────────────
    if has_analysis:
        issues     = ss.get("issues", [])
        sev_counts: dict[str, int] = {}
        for iss in issues:
            s = _issue_severity(iss)
            sev_counts[s] = sev_counts.get(s, 0) + 1

        order = ["critical", "high", "medium", "low", "info"]
        chips = " ".join(
            f'<span style="font-size:9px;font-family:JetBrains Mono,monospace;'
            f'color:{_SEV_COLOUR[s]};background:{_SEV_COLOUR[s]}18;'
            f'border-radius:3px;padding:1px 5px;">{cnt}{s[0].upper()}</span>'
            for s in order if (cnt := sev_counts.get(s, 0)) > 0
        )
        rows.append(("🔴 Red Team", chips or '<span style="color:#3dba6e;font-size:10px;">clean ✓</span>'))
    else:
        rows.append(("🔴 Red Team", '<span style="color:#3d5166;font-size:10px;">not run yet</span>'))

    # ── Blue Team status ───────────────────────────────────────────────────
    if has_fixes:
        fixes = ss.get("fixes", [])
        auto  = sum(1 for f in fixes if _get(f, "fix_type", "") in ("automated", "semi_automated"))
        man   = sum(1 for f in fixes if _get(f, "fix_type", "") == "manual")
        rows.append(("🔵 Blue Team",
            f'<span style="color:#3dba6e;font-size:9px;font-family:JetBrains Mono,monospace;">{auto} auto</span>'
            f'<span style="color:#6b8299;font-size:9px;font-family:JetBrains Mono,monospace;"> · {man} manual</span>'))
    else:
        rows.append(("🔵 Blue Team", '<span style="color:#3d5166;font-size:10px;">not run yet</span>'))

    # ── Monte Carlo status ─────────────────────────────────────────────────
    if has_simulation:
        sim = ss.get("simulation_result")
        pct = (sim.get("risk_reduction_percentage", 0)
               if isinstance(sim, dict)
               else getattr(sim, "risk_reduction_percentage", 0) or 0)
        colour = "#3dba6e" if pct >= 30 else "#d9a83a"
        rows.append(("📊 Monte Carlo",
            f'<span style="color:{colour};font-size:9px;font-family:JetBrains Mono,monospace;">'
            f'↓ {pct:.0f}% risk</span>'))
    else:
        rows.append(("📊 Monte Carlo", '<span style="color:#3d5166;font-size:10px;">not run yet</span>'))

    for label, value_html in rows:
        st.sidebar.markdown(
            f"""
            <div style="padding:5px 14px;margin:1px 0;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                            color:#6b8299;margin-bottom:2px;">{label}</div>
                <div>{value_html}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _render_settings(ss) -> None:
    """LLM toggle + API key input at the very bottom of the sidebar."""
    _section_label("Settings")

    st.sidebar.toggle(
        "🤖 LLM Explainer",
        key="llm_enabled",
        help="Enables the optional AI explanation layer. "
             "AI is used for natural language explanation ONLY — "
             "never for security decisions.",
    )

    if ss.get("llm_enabled"):
        api_val = st.sidebar.text_input(
            "OpenAI API Key",
            value=ss.get("llm_api_key", ""),
            type="password",
            placeholder="sk-...",
            key="llm_api_key_sidebar",
            help="Stored in this session only, never logged or transmitted externally.",
        )
        st.session_state["llm_api_key"] = api_val

    # Bottom footer
    st.sidebar.markdown(
        """
        <div style="padding:16px 14px 8px;text-align:center;
                    font-family:'JetBrains Mono',monospace;
                    font-size:9px;color:#1e3650;line-height:1.6;">
            CN6000 · LSBF Singapore · 2026<br>
            Qian Zhu · S1034134
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def render_sidebar(current_page: str = "") -> None:
    """
    Render the full shared sidebar on any page.

    Parameters
    ----------
    current_page : str
        Label of the current page. Controls which nav item is highlighted
        and which items are locked.

        Valid values:
            "Home" | "Upload" | "Red Team" | "Blue Team" |
            "Risk Analysis" | "AI Explainer" | "Reports"
    """
    # Inject CSS (idempotent — Streamlit deduplicates markdown)
    st.markdown(_SIDEBAR_CSS, unsafe_allow_html=True)

    # Ensure all session keys exist before reading them
    _defaults = {
        "file_name": "", "file_type": "", "raw_content": "",
        "config_file": None, "issues": [], "fixes": [],
        "selected_fix_ids": set(), "simulation_result": None,
        "analysis_ran": False, "fixes_generated": False,
        "simulation_ran": False, "llm_enabled": False,
        "llm_api_key": "", "chat_history": [],
    }
    for k, v in _defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

    ss = st.session_state

    # Unlock rules — each page requires its prerequisites to be complete
    has_file     = bool(ss.get("file_name"))
    has_analysis = bool(ss.get("analysis_ran") and ss.get("issues"))

    unlocked = {
        "Home":          True,           # always accessible
        "Upload":        True,           # always accessible
        "Red Team":      has_file,       # need an uploaded file
        "Blue Team":     has_analysis,   # need Red Team results
        "Risk Analysis": has_analysis,   # need Red Team results
        "AI Explainer":  has_analysis,   # need Red Team results
        "Reports":       has_analysis,   # need Red Team results
    }

    # Render all sections top to bottom
    _render_logo()
    _render_new_analysis_button()
    _render_file_chip(ss)
    _divider()
    _render_nav(current_page, unlocked)
    _divider()
    _render_session_status(ss)
    _divider()
    _render_settings(ss)
