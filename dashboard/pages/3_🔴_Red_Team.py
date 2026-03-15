"""
pages/3_🔴_Red_Team.py
~~~~~~~~~~~~~~~~~~~~~~~
Red Team Analysis page — run deterministic rule-based security review.
"""

import time
from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.components.sidebar import render_sidebar
from dashboard.components.ui_helpers import _attr as _get

st.set_page_config(
    page_title="Red Team — SecConfig",
    page_icon="🔴",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

render_sidebar(current_page="Red Team")


# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                   color:#c9d8e8;margin:0;">
            🔴 Red Team Analysis
        </h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Deterministic rule-based security review · 23 rules · No AI involvement
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.raw_content:
    st.warning("⚠️ No configuration file loaded. Please upload a file first.")
    if st.button("📤 Go to Upload"):
        st.switch_page("pages/2_📤_Upload.py")
    st.stop()

# ── Run analysis ───────────────────────────────────────────────────────────────
if not st.session_state.analysis_ran:
    col_btn, col_info = st.columns([2, 3])
    with col_btn:
        if st.button("🔴  Start Red Team Analysis", type="primary", use_container_width=True):
            with st.spinner("Running rule engine..."):
                try:
                    from src.parsers.parser_factory import ParserFactory
                    from src.core.red_team.analyzer import RedTeamAnalyzer

                    parser = ParserFactory.get_parser(st.session_state.file_type)
                    config = parser.parse(st.session_state.raw_content,
                                         st.session_state.file_name)

                    progress = st.progress(0, text="Loading rules...")
                    analyzer = RedTeamAnalyzer()
                    progress.progress(30, text="Applying rules...")
                    issues = analyzer.analyze(config)
                    progress.progress(100, text="Done.")
                    time.sleep(0.3)
                    progress.empty()

                    st.session_state.config_file  = config
                    st.session_state.issues        = issues
                    st.session_state.analysis_ran  = True
                    # Reset downstream artifacts so fixes/simulation always match
                    # the latest detected issue set.
                    st.session_state.fixes = []
                    st.session_state.fixes_generated = False
                    st.session_state.selected_fix_ids = set()
                    st.session_state.simulation_ran = False
                    st.session_state.simulation_result = None
                    st.session_state.report = None
                    st.rerun()

                except Exception as exc:
                    st.error(f"Analysis error: {exc}")
                    st.info("Running demo mode with mock issues for demonstration.")

                    # Demo mock issues
                    from src.models.issue_model import SecurityIssue, RiskProfile
                    from datetime import datetime

                    mock_issues = [
                        {"rule_id":"CRED-001","title":"Hard-coded Password","severity":"critical",
                         "category":"credentials","line_number":3,
                         "description":"A password is hard-coded directly in the configuration file.",
                         "vulnerable_code":"DATABASE_PASSWORD=admin123",
                         "remediation_hint":"Replace with environment variable reference: ${DATABASE_PASSWORD}",
                         "nist_function":"PROTECT","cwe_id":"CWE-798"},
                        {"rule_id":"BASE-001","title":"Debug Mode Enabled","severity":"high",
                         "category":"baseline","line_number":7,
                         "description":"Application is running in debug mode exposing sensitive information.",
                         "vulnerable_code":"DEBUG=true",
                         "remediation_hint":"Set DEBUG=false in production environments.",
                         "nist_function":"PROTECT","cwe_id":"CWE-11"},
                        {"rule_id":"ENC-001","title":"Weak Encryption Algorithm","severity":"high",
                         "category":"encryption","line_number":12,
                         "description":"MD5/DES is cryptographically broken and should not be used.",
                         "vulnerable_code":"ENCRYPTION_ALGORITHM=MD5",
                         "remediation_hint":"Use AES-256-GCM or ChaCha20-Poly1305.",
                         "nist_function":"PROTECT","cwe_id":"CWE-327"},
                        {"rule_id":"AC-001","title":"Wildcard CORS Policy","severity":"medium",
                         "category":"access_control","line_number":5,
                         "description":"CORS allows all origins (*), enabling cross-site request attacks.",
                         "vulnerable_code":"CORS_ORIGIN=*",
                         "remediation_hint":"Restrict to specific trusted origins.",
                         "nist_function":"PROTECT","cwe_id":"CWE-942"},
                        {"rule_id":"LOG-001","title":"Logging Disabled","severity":"medium",
                         "category":"logging","line_number":9,
                         "description":"Logging is disabled, preventing security event detection.",
                         "vulnerable_code":"LOG_LEVEL=none",
                         "remediation_hint":"Enable logging at INFO or higher level.",
                         "nist_function":"DETECT","cwe_id":"CWE-778"},
                        {"rule_id":"CRED-004","title":"API Key Exposed","severity":"critical",
                         "category":"credentials","line_number":6,
                         "description":"API key is hard-coded and may be committed to version control.",
                         "vulnerable_code":"API_KEY=sk-live-abc123xyz789",
                         "remediation_hint":"Move API key to a secrets manager or environment variable.",
                         "nist_function":"PROTECT","cwe_id":"CWE-312"},
                    ]

                    st.session_state.issues       = mock_issues
                    st.session_state.config_file  = None
                    st.session_state.analysis_ran = True
                    # Keep downstream state consistent in demo mode as well.
                    st.session_state.fixes = []
                    st.session_state.fixes_generated = False
                    st.session_state.selected_fix_ids = set()
                    st.session_state.simulation_ran = False
                    st.session_state.simulation_result = None
                    st.session_state.report = None
                    st.rerun()

    with col_info:
        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;padding:14px 18px;">
                <div style="font-size:10px;color:#3d5166;font-family:'JetBrains Mono',monospace;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px;">Ready to analyse</div>
                <div style="font-size:13px;color:#c9d8e8;">
                    📄 <strong>{st.session_state.file_name}</strong>
                </div>
                <div style="font-size:12px;color:#6b8299;margin-top:4px;">
                    23 rules · credentials · encryption · access control · logging · baseline
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

else:
    # ── Results ────────────────────────────────────────────────────────────────
    issues = st.session_state.issues


    # Summary metrics
    severities = [_get(i, "severity", "info").lower() for i in issues]
    sev_counts = {s: severities.count(s) for s in ["critical","high","medium","low","info"] if s in severities}

    c1, c2, c3, c4, c5 = st.columns(5)
    col_map = {"critical": c1, "high": c2, "medium": c3, "low": c4}
    sev_colours_map = {
        "critical": "#f04f47", "high": "#e88c3a",
        "medium": "#d9a83a",   "low": "#3dba6e",
    }

    for col, (sev, colour) in zip([c1, c2, c3, c4], sev_colours_map.items()):
        with col:
            count = sev_counts.get(sev, 0)
            st.markdown(
                f"""
                <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                            padding:14px 16px;text-align:center;border-top:2px solid {colour};">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                                color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;">
                        {sev}
                    </div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                                color:{colour};margin:4px 0;">{count}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    with c5:
        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                        padding:14px 16px;text-align:center;border-top:2px solid #3b8ef3;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                            color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;">
                    total
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            color:#3b8ef3;margin:4px 0;">{len(issues)}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # Charts
    from dashboard.components.chart_adapter import severity_donut, category_bar

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        if sev_counts:
            st.plotly_chart(severity_donut(sev_counts, height=280), use_container_width=True)
    with chart_col2:
        cats = {}
        for issue in issues:
            cat = _get(issue, "category", "unknown")
            cats[cat] = cats.get(cat, 0) + 1
        if cats:
            st.plotly_chart(category_bar(cats, height=280), use_container_width=True)

    st.markdown("---")

    # Filters
    col_f1, col_f2, col_f3 = st.columns(3)
    with col_f1:
        sev_filter = st.multiselect(
            "Filter by severity",
            options=["critical","high","medium","low","info"],
            default=[],
        )
    with col_f2:
        cat_filter = st.multiselect(
            "Filter by category",
            options=["credentials","encryption","access_control","logging","baseline"],
            default=[],
        )
    with col_f3:
        nist_filter = st.multiselect(
            "Filter by NIST function",
            options=["IDENTIFY","PROTECT","DETECT","RESPOND","RECOVER"],
            default=[],
        )

    # Apply filters
    filtered = issues
    if sev_filter:
        filtered = [i for i in filtered if _get(i,"severity","").lower() in sev_filter]
    if cat_filter:
        filtered = [i for i in filtered if _get(i,"category","").lower() in cat_filter]
    if nist_filter:
        filtered = [i for i in filtered if _get(i,"nist_function","").upper() in nist_filter]

    st.markdown(
        f'<div style="font-size:12px;color:#3d5166;font-family:\'JetBrains Mono\',monospace;'
        f'margin-bottom:12px;">Showing {len(filtered)} of {len(issues)} issues</div>',
        unsafe_allow_html=True,
    )

    # Issue cards
    NIST_ICONS_MAP = {"IDENTIFY":"🔍","PROTECT":"🛡️","DETECT":"📡","RESPOND":"⚡","RECOVER":"🔄"}
    SEV_ICONS_MAP  = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢","info":"🔵"}
    SEV_COL_MAP    = {"critical":"#f04f47","high":"#e88c3a","medium":"#d9a83a","low":"#3dba6e","info":"#3b8ef3"}

    for idx, issue in enumerate(filtered):
        sev   = _get(issue, "severity", "info").lower()
        title = _get(issue, "title", "Unknown Issue")
        rule  = _get(issue, "rule_id", "")
        line  = _get(issue, "line_number", "?")
        icon  = SEV_ICONS_MAP.get(sev, "⚪")
        colour= SEV_COL_MAP.get(sev, "#6b8299")

        with st.expander(f"{icon} [{rule}] {title}  —  Line {line}", expanded=False):
            r1, r2, r3 = st.columns(3)
            with r1:
                st.markdown(
                    f'**Severity:** <span style="color:{colour};font-family:\'JetBrains Mono\','
                    f'monospace;font-size:11px;text-transform:uppercase;">{sev}</span>',
                    unsafe_allow_html=True,
                )
            with r2:
                cat = _get(issue, "category", "")
                st.markdown(f"**Category:** `{cat.replace('_',' ').title()}`")
            with r3:
                nist = _get(issue, "nist_function", "")
                cwe  = _get(issue, "cwe_id", "")
                nist_icon = NIST_ICONS_MAP.get(nist.upper(), "")
                st.markdown(f"**NIST:** {nist_icon} {nist} | **CWE:** {cwe}")

            st.markdown("---")
            desc = _get(issue, "description", "")
            if desc:
                st.markdown(f"**Description:** {desc}")

            vuln = _get(issue, "vulnerable_code", "")
            if vuln:
                st.markdown(f"**Vulnerable Code** (line {line}):")
                st.code(vuln, language="bash")

            hint = _get(issue, "remediation_hint", "")
            if hint:
                st.info(f"💡 **Remediation hint:** {hint}")

    # CTA
    st.markdown("<br>", unsafe_allow_html=True)
    col_a, col_b, col_c = st.columns([2, 2, 1])
    with col_a:
        if st.button("🔵 Generate Blue Team Fixes", type="primary", use_container_width=True):
            st.switch_page("pages/4_🔵_Blue_Team.py")
    with col_b:
        if st.button("📊 Skip to Risk Simulation", use_container_width=True):
            st.switch_page("pages/5_📊_Risk_Analysis.py")
    with col_c:
        if st.button("🔄 Re-run Analysis", use_container_width=True):
            st.session_state.analysis_ran = False
            st.session_state.issues = []
            st.session_state.fixes = []
            st.session_state.fixes_generated = False
            st.session_state.selected_fix_ids = set()
            st.session_state.simulation_ran = False
            st.session_state.simulation_result = None
            st.session_state.report = None
            st.rerun()