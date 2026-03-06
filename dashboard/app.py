"""
dashboard/app.py
~~~~~~~~~~~~~~~~
SecConfig Analyzer — Streamlit Application Entry Point.

Run with:
    streamlit run dashboard/app.py
"""

from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from components.sidebar import render_sidebar

# ── Page config (must be first Streamlit call) ────────────────────────────────
st.set_page_config(
    page_title="SecConfig Analyzer",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Load CSS ──────────────────────────────────────────────────────────────────
css_path = Path(__file__).parent / "styles" / "custom.css"
if css_path.exists():
    with open(css_path) as f:
        st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

render_sidebar(current_page="Home")

# ── Session state defaults ────────────────────────────────────────────────────
defaults = {
    "config_file":        None,   # parsed ConfigFile object
    "raw_content":        "",     # raw text of uploaded file
    "file_name":          "",
    "file_type":          "",
    "issues":             [],     # List[SecurityIssue]
    "fixes":              [],     # List[SecurityFix]
    "selected_fix_ids":   set(),
    "simulation_result":  None,   # SimulationResult
    "report":             None,   # AnalysisReport
    "analysis_ran":       False,
    "fixes_generated":    False,
    "simulation_ran":     False,
    "llm_enabled":        False,
    "llm_api_key":        "",
    "chat_history":       [],
    "user_background":    "junior_dev",
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# ── Home page content ─────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="text-align:center;">
        <div style="font-size:3.5rem;margin-bottom:16px;">🔒</div>
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:2.2rem;
                   color:#c9d8e8;margin:0;letter-spacing:-0.03em;">
            SecConfig Analyzer
        </h1>
        <p style="color:#6b8299;font-size:15px;margin-top:12px;max-width:600px;margin-left:auto;margin-right:auto;">
            AI-Augmented Red Team / Blue Team Framework for Configuration Security Analysis
            with Monte Carlo Risk Simulation
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Feature cards
cards = [
    ("🔴", "Red Team", "Deterministic rule-based security review across 23 rules covering credentials, encryption, access control, logging, and baseline settings.", "#f04f47"),
    ("🔵", "Blue Team", "Template-based automated remediation engine that generates fix suggestions and validates changes before application.", "#3b8ef3"),
    ("📊", "Monte Carlo", "Probabilistic risk quantification using 10,000-iteration simulation with Beta distributions to compare pre/post remediation risk.", "#3dba6e"),
    ("💬", "AI Explainer", "Optional isolated LLM layer (disabled by default) that translates deterministic findings into natural language for non-expert users.", "#26d4d4"),
]

cards_html = ""
for icon, title, desc, colour in cards:
    cards_html += f'<div style="background:#101820;border:1px solid #1a2838;border-radius:10px;padding:20px 16px;"><div style="font-size:1.6rem;margin-bottom:10px;">{icon}</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:13px;font-weight:600;color:{colour};margin-bottom:8px;">{title}</div><div style="font-size:12px;color:#6b8299;line-height:1.6;">{desc}</div></div>'

st.markdown(
    '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;margin-bottom:24px;">' + cards_html + '</div>',
    unsafe_allow_html=True,
)

# Workflow steps — all in one markdown call
steps = [
    ("📤", "Upload",    "Upload .env / .yaml / .json"),
    ("🔴", "Detect",    "Red Team scans 23 rules"),
    ("🔵", "Remediate", "Blue Team generates fixes"),
    ("📊", "Simulate",  "Monte Carlo risk score"),
    ("📋", "Report",    "Export findings"),
]

step_html = ""
for i, (icon, name, desc) in enumerate(steps):
    arrow = '<span style="color:#1e3650;font-size:1.4rem;margin:0 8px;">→</span>' if i < len(steps) - 1 else ""
    step_html += f'<div style="display:flex;flex-direction:column;align-items:center;min-width:90px;text-align:center;"><div style="font-size:1.4rem;margin-bottom:6px;">{icon}</div><div style="font-family:\'JetBrains Mono\',monospace;font-size:12px;color:#c9d8e8;font-weight:600;">{name}</div><div style="font-size:11px;color:#3d5166;margin-top:4px;">{desc}</div></div>{arrow}'

step_html = step_html.strip()

st.markdown(
    '<div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;padding:24px 28px;margin-bottom:24px;">'
    '<div style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;margin-bottom:16px;">Workflow</div>'
    '<div style="display:flex;align-items:center;gap:4px;flex-wrap:wrap;">'
    + step_html +
    '</div></div>',
    unsafe_allow_html=True,
)

# Quick start CTA
col_l, col_c, col_r = st.columns([1, 2, 1])
with col_c:
    if st.button("🚀  Get Started — Upload Config File", use_container_width=True, type="primary"):
        st.switch_page("pages/2_📤_Upload.py")

# NIST alignment note
st.markdown(
    """
    <div style="margin-top:24px;padding:16px 20px;background:#101820;border-radius:8px;
                border-left:3px solid #3b8ef3;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">
            NIST Cybersecurity Framework Alignment
        </div>
        <div style="font-size:13px;color:#6b8299;line-height:1.7;">
            Services are structured around the five NIST CSF functions:
            <span style="color:#c9d8e8;">IDENTIFY</span> →
            <span style="color:#c9d8e8;">PROTECT</span> →
            <span style="color:#c9d8e8;">DETECT</span> →
            <span style="color:#c9d8e8;">RESPOND</span> →
            <span style="color:#c9d8e8;">RECOVER</span>.
            All configuration files analysed are synthetic. No real production data is used.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown('<div style="height:50px;"></div>', unsafe_allow_html=True)
st.markdown(
    '<div style="position:fixed;bottom:0;left:0;right:0;background:#0c1118;border-top:1px solid #1a2838;padding:10px 32px;display:flex;justify-content:space-between;align-items:center;z-index:999; margin-top:24px;">'
    '<span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#3d5166;">🔒 SecConfig Analyzer v1.0 · CN6000 MWPL Project · BSc Hons Cyber Security &amp; Networks</span>'
    '<span style="font-family:\'JetBrains Mono\',monospace;font-size:11px;color:#3d5166;">Qian Zhu · S1034134 · Supervisor: Dr. Preethi Kesavan · LSBF Singapore · 2026</span>'
    '</div>',
    unsafe_allow_html=True,
)