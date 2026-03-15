"""
pages/4_🔵_Blue_Team.py
~~~~~~~~~~~~~~~~~~~~~~~~
Blue Team Remediation page — template-based fix generation.
"""

from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.components.sidebar import render_sidebar
from dashboard.components.ui_helpers import _attr as _get

st.set_page_config(
    page_title="Blue Team — SecConfig",
    page_icon="🔵",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

for key, val in [("issues",[]),("fixes",[]),("analysis_ran",False),
                  ("fixes_generated",False),("selected_fix_ids",set())]:
    if key not in st.session_state:
        st.session_state[key] = val

# Reset old checkbox widget states before any widgets are instantiated.
if st.session_state.pop("_reset_fix_checkboxes", False):
    for k in list(st.session_state.keys()):
        if k.startswith("chk_fix_"):
            st.session_state.pop(k, None)

render_sidebar(current_page="Blue Team")

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;color:#c9d8e8;margin:0;">
            🔵 Blue Team Remediation
        </h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Template-based fix generation · Deterministic · No AI involvement
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.analysis_ran and not st.session_state.issues:
    st.warning("⚠️ No analysis results found. Please run Red Team analysis first.")
    if st.button("🔴 Go to Red Team Analysis"):
        st.switch_page("pages/3_🔴_Red_Team.py")
    st.stop()

issues = st.session_state.issues


# ── Generate fixes ─────────────────────────────────────────────────────────────
if not st.session_state.fixes_generated:
    col_btn, col_info = st.columns([2, 3])
    with col_btn:
        if st.button("🔵  Generate Remediation Fixes", type="primary", use_container_width=True):
            with st.spinner("Generating fixes..."):
                try:
                    from src.core.blue_team.remediator import BlueTeamRemediator
                    remediator = BlueTeamRemediator()
                    fixes = remediator.remediate(issues)
                    st.session_state.fixes = fixes
                    st.session_state.fixes_generated = True
                    st.rerun()
                except Exception as exc:
                    st.info(f"Using demo fixes (engine: {exc})")
                    # Demo mock fixes
                    mock_fixes = []
                    fix_templates = {
                        "CRED-001": {
                            "fix_type": "automated",
                            "original_code": "DATABASE_PASSWORD=admin123",
                            "fixed_code": "DATABASE_PASSWORD=${DATABASE_PASSWORD}",
                            "explanation": "Replace hard-coded value with environment variable reference.",
                            "strategy": "template_replacement",
                            "priority": "immediate",
                            "effort": "low",
                            "side_effects": ["Set DATABASE_PASSWORD in your deployment environment"],
                            "risk_reduction": 0.85,
                        },
                        "BASE-001": {
                            "fix_type": "automated",
                            "original_code": "DEBUG=true",
                            "fixed_code": "DEBUG=false",
                            "explanation": "Disable debug mode to prevent information disclosure.",
                            "strategy": "configuration_change",
                            "priority": "immediate",
                            "effort": "low",
                            "side_effects": [],
                            "risk_reduction": 0.70,
                        },
                        "ENC-001": {
                            "fix_type": "semi_automated",
                            "original_code": "ENCRYPTION_ALGORITHM=MD5",
                            "fixed_code": "ENCRYPTION_ALGORITHM=AES-256-GCM",
                            "explanation": "Replace broken MD5 with AES-256-GCM. Update application code accordingly.",
                            "strategy": "configuration_change",
                            "priority": "high",
                            "effort": "medium",
                            "side_effects": ["Requires application code changes for new cipher"],
                            "risk_reduction": 0.80,
                        },
                        "AC-001": {
                            "fix_type": "automated",
                            "original_code": "CORS_ORIGIN=*",
                            "fixed_code": "CORS_ORIGIN=https://your-domain.com",
                            "explanation": "Restrict CORS to specific trusted origins.",
                            "strategy": "template_replacement",
                            "priority": "high",
                            "effort": "low",
                            "side_effects": ["Update CORS_ORIGIN with your actual domain"],
                            "risk_reduction": 0.65,
                        },
                        "LOG-001": {
                            "fix_type": "automated",
                            "original_code": "LOG_LEVEL=none",
                            "fixed_code": "LOG_LEVEL=info",
                            "explanation": "Enable logging to detect security events.",
                            "strategy": "configuration_change",
                            "priority": "high",
                            "effort": "low",
                            "side_effects": [],
                            "risk_reduction": 0.60,
                        },
                        "CRED-004": {
                            "fix_type": "automated",
                            "original_code": "API_KEY=sk-live-abc123xyz789",
                            "fixed_code": "API_KEY=${API_KEY}",
                            "explanation": "Move API key to environment variable or secrets manager.",
                            "strategy": "template_replacement",
                            "priority": "immediate",
                            "effort": "low",
                            "side_effects": ["Set API_KEY in your secrets manager"],
                            "risk_reduction": 0.90,
                        },
                    }
                    for i, issue in enumerate(issues):
                        rule_id = _get(issue, "rule_id", "")
                        template = fix_templates.get(rule_id, {
                            "fix_type": "manual",
                            "original_code": _get(issue, "vulnerable_code", ""),
                            "fixed_code": "",
                            "explanation": _get(issue, "remediation_hint", "Manual fix required."),
                            "strategy": "manual_guidance",
                            "priority": "medium",
                            "effort": "medium",
                            "side_effects": [],
                            "risk_reduction": 0.40,
                        })
                        mock_fixes.append({
                            "fix_id": f"FIX-{i+1:03d}",
                            "issue_id": _get(issue, "issue_id", f"ISSUE-{i+1:03d}"),
                            "issue_title": _get(issue, "title", "Unknown"),
                            "rule_id": rule_id,
                            "validation_status": "validated",
                            **template,
                        })
                    st.session_state.fixes = mock_fixes
                    st.session_state.fixes_generated = True
                    st.rerun()

    with col_info:
        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;padding:14px 18px;">
                <div style="font-size:10px;color:#3d5166;font-family:'JetBrains Mono',monospace;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:8px;">Ready</div>
                <div style="font-size:13px;color:#c9d8e8;">
                    {len(issues)} issues queued for remediation
                </div>
                <div style="font-size:12px;color:#6b8299;margin-top:4px;">
                    Template-based · Deterministic · Validates before applying
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

else:
    # ── Show fixes ─────────────────────────────────────────────────────────────
    fixes = st.session_state.fixes
    all_fix_ids = {_get(f, "fix_id", str(id(f))) for f in fixes}

    # Keep selected ids aligned with currently visible fixes.
    st.session_state.selected_fix_ids = (
        set(st.session_state.selected_fix_ids).intersection(all_fix_ids)
    )

    # Process bulk actions before any checkbox widgets are rendered.
    bulk_action = st.session_state.pop("_bulk_fix_action", "")
    if bulk_action == "select_all":
        st.session_state.selected_fix_ids = set(all_fix_ids)
        for k in list(st.session_state.keys()):
            if k.startswith("chk_fix_"):
                st.session_state.pop(k, None)

    # Summary metrics
    auto_count  = sum(1 for f in fixes if _get(f,"fix_type","") == "automated")
    semi_count  = sum(1 for f in fixes if _get(f,"fix_type","") == "semi_automated")
    man_count   = sum(1 for f in fixes if _get(f,"fix_type","") == "manual")
    valid_count = sum(1 for f in fixes if _get(f,"validation_status","") == "validated")

    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, colour in [
        (c1, "automated", auto_count,  "#3dba6e"),
        (c2, "semi-auto", semi_count,  "#d9a83a"),
        (c3, "manual",    man_count,   "#6b8299"),
        (c4, "validated", valid_count, "#3b8ef3"),
    ]:
        with col:
            st.markdown(
                f"""
                <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                            padding:14px 16px;text-align:center;border-top:2px solid {colour};">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                                color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;">
                        {label}
                    </div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                                color:{colour};margin:4px 0;">{val}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("<br>", unsafe_allow_html=True)

    # Fix type tabs
    tab_all, tab_auto, tab_manual = st.tabs(["All Fixes", "Automated", "Manual Guidance"])

    def _render_fix(fix, tab_prefix="all", selectable=True):
        fix_type = _get(fix, "fix_type", "manual")
        title    = _get(fix, "issue_title", "Unknown")
        priority = _get(fix, "priority", "medium")
        effort   = _get(fix, "effort", "medium")
        val_status = _get(fix, "validation_status", "pending")
        fix_id   = _get(fix, "fix_id", str(id(fix)))

        type_colour = {"automated":"#3dba6e","semi_automated":"#d9a83a","manual":"#6b8299"}
        type_icon   = {"automated":"🤖","semi_automated":"🔧","manual":"📋"}
        colour = type_colour.get(fix_type, "#6b8299")
        icon   = type_icon.get(fix_type, "📋")

        priority_colour = {"immediate":"#f04f47","high":"#e88c3a","medium":"#d9a83a","low":"#3dba6e"}
        pcolour = priority_colour.get(priority, "#6b8299")

        with st.expander(f"{icon} {title}", expanded=False):
            r1, r2, r3, r4 = st.columns(4)
            with r1:
                st.markdown(
                    f'<span style="color:{colour};font-family:\'JetBrains Mono\',monospace;font-size:11px;">'
                    f'⬤ {fix_type.replace("_"," ").upper()}</span>',
                    unsafe_allow_html=True,
                )
            with r2:
                st.markdown(
                    f'**Priority:** <span style="color:{pcolour};">`{priority}`</span>',
                    unsafe_allow_html=True,
                )
            with r3:
                st.markdown(f"**Effort:** `{effort}`")
            with r4:
                vs_colour = "#3dba6e" if val_status == "validated" else "#e88c3a"
                st.markdown(
                    f'**Valid:** <span style="color:{vs_colour};">`{val_status}`</span>',
                    unsafe_allow_html=True,
                )

            original = _get(fix, "original_code", "")
            fixed    = _get(fix, "fixed_code", "")
            if original or fixed:
                st.markdown("---")
                left, right = st.columns(2)
                with left:
                    st.markdown("🔴 **Before**")
                    st.code(original or "(none)", language="bash")
                with right:
                    st.markdown("🟢 **After**")
                    st.code(fixed or "(manual fix required)", language="bash")

            explanation = _get(fix, "explanation", "")
            if explanation:
                st.markdown(f"**Explanation:** {explanation}")

            side_effects = _get(fix, "side_effects", [])
            if side_effects:
                st.warning("⚠️ **Side effects:** " + " · ".join(side_effects))

            risk_red = _get(fix, "risk_reduction", 0)
            if risk_red:
                st.markdown(
                    f'<div style="font-size:12px;color:#3dba6e;font-family:\'JetBrains Mono\','
                    f'monospace;">Expected risk reduction: {risk_red*100:.0f}%</div>',
                    unsafe_allow_html=True,
                )

            if selectable:
                chk_key = f"chk_fix_{fix_id}"
                if chk_key not in st.session_state:
                    st.session_state[chk_key] = fix_id in st.session_state.selected_fix_ids

                selected = st.checkbox(
                    "Apply this fix",
                    key=chk_key,
                )
                if selected:
                    st.session_state.selected_fix_ids.add(fix_id)
                else:
                    st.session_state.selected_fix_ids.discard(fix_id)

    with tab_all:
        for fix in fixes:
            _render_fix(fix, tab_prefix="all", selectable=True)

    with tab_auto:
        auto_fixes = [f for f in fixes if _get(f,"fix_type","") in ("automated","semi_automated")]
        if auto_fixes:
            for fix in auto_fixes:
                _render_fix(fix, tab_prefix="auto", selectable=False)
        else:
            st.info("No automated fixes available.")

    with tab_manual:
        man_fixes = [f for f in fixes if _get(f,"fix_type","") == "manual"]
        if man_fixes:
            for fix in man_fixes:
                _render_fix(fix, tab_prefix="manual", selectable=False)
        else:
            st.info("No manual fixes in this set.")

    # Selection summary
    n_selected = len(st.session_state.selected_fix_ids)
    st.markdown(
        f"""
        <div style="background:#101820;border:1px solid #1e3650;border-radius:8px;
                    padding:14px 20px;margin:16px 0;display:flex;
                    align-items:center;justify-content:space-between;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:#c9d8e8;">
                <strong style="color:#3b8ef3;">{n_selected}</strong> fixes selected
                &nbsp;·&nbsp;
                <span style="color:#6b8299;">{len(fixes) - n_selected} unselected</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_a, col_b, col_c = st.columns([2, 2, 1])
    with col_a:
        if st.button("📊 Run Risk Simulation", type="primary", use_container_width=True):
            st.switch_page("pages/5_📊_Risk_Analysis.py")
    with col_b:
        # Select all
        if st.button("Select All Fixes", use_container_width=True):
            st.session_state["_bulk_fix_action"] = "select_all"
            st.rerun()
    with col_c:
        if st.button("🔄 Regenerate", use_container_width=True):
            st.session_state["_reset_fix_checkboxes"] = True
            st.session_state["_bulk_fix_action"] = ""
            st.session_state.fixes_generated = False
            st.session_state.fixes = []
            st.session_state.selected_fix_ids = set()
            st.rerun()