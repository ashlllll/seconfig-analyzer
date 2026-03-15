"""
pages/6_💬_AI_Explainer.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~
Optional LLM Explainer — isolated, post-analysis explanation only.
"""

from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.components.sidebar import render_sidebar
from dashboard.components.ui_helpers import _attr as _get

st.set_page_config(
    page_title="AI Explainer — SecConfig",
    page_icon="💬",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

for key, val in [("llm_enabled",False),("llm_api_key",""),("chat_history",[]),
                  ("issues",[]),("fixes",[]),("simulation_result",None),
                  ("user_background","junior_dev")]:
    if key not in st.session_state:
        st.session_state[key] = val

render_sidebar(current_page="AI Explainer")

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;color:#c9d8e8;margin:0;">
            💬 AI Explainer
        </h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Optional LLM layer · Post-analysis explanation only · 
            Does not influence security decisions
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Isolation notice ───────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="background:#101820;border:1px solid #1e3650;border-radius:8px;
                padding:14px 20px;margin-bottom:20px;border-left:3px solid #3b8ef3;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">
            Architecture note
        </div>
        <div style="font-size:13px;color:#6b8299;">
            The LLM is <strong style="color:#c9d8e8;">strictly isolated</strong> as a post-analysis 
            explanation module. It receives only the deterministic results as context and 
            <strong style="color:#c9d8e8;">does not participate</strong> in detection, remediation, 
            or risk scoring. All security decisions are made by the rule engine.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.llm_enabled:
    # Disabled state
    col_main, col_side = st.columns([3, 2])
    with col_main:
        st.markdown(
            """
            <div style="text-align:center;padding:60px 20px;color:#3d5166;">
                <div style="font-size:3rem;margin-bottom:14px;">🤖</div>
                <p style="font-size:15px;color:#6b8299;">LLM Explainer is currently disabled</p>
                <p style="font-size:13px;color:#3d5166;margin-top:8px;">
                    Enable it in the sidebar toggle and provide an OpenAI API key to use this feature.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;padding:20px 24px;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px;">
                    Example questions you can ask
                </div>
            """,
            unsafe_allow_html=True,
        )
        example_qs = [
            "Why is CRED-001 classified as critical severity?",
            "How do I fix the hard-coded password issue?",
            "Can you explain the Monte Carlo risk reduction result?",
            "What does the NIST PROTECT function cover in this analysis?",
            "Which issue should I fix first and why?",
            "What are the business implications of these findings?",
        ]
        for q in example_qs:
            st.markdown(
                f'<div style="padding:8px 12px;margin:4px 0;background:#101820;border:1px solid #1a2838;'
                f'border-radius:6px;font-size:13px;color:#6b8299;font-family:\'JetBrains Mono\',monospace;">'
                f'"{q}"</div>',
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with col_side:
        st.markdown(
            """
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;padding:20px;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:14px;">
                    How to enable
                </div>
                <ol style="color:#6b8299;font-size:13px;line-height:2;padding-left:20px;">
                    <li>Open the sidebar</li>
                    <li>Toggle <strong style="color:#c9d8e8;">🤖 LLM Explainer</strong></li>
                    <li>Enter your OpenAI API key</li>
                    <li>Return to this page</li>
                </ol>
                <div style="margin-top:14px;padding:12px;background:#101820;border-radius:6px;
                            border:1px solid #1a2838;">
                    <div style="font-size:11px;color:#3d5166;margin-bottom:6px;">Supported backgrounds</div>
                    <div style="font-size:12px;color:#c9d8e8;line-height:1.8;">
                        🎓 Junior Developer<br>
                        💼 Manager / Non-technical<br>
                        🔐 Security Expert
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

else:
    # Enabled state — chat interface
    col_chat, col_ctx = st.columns([3, 1])

    with col_ctx:
        # Context panel
        issues  = st.session_state.issues
        fixes   = st.session_state.fixes
        sim_res = st.session_state.simulation_result

        n_issues   = len(issues)
        n_critical = sum(1 for i in issues if _get(i,"severity","").lower() == "critical")
        sim_before = 0.0
        sim_after  = 0.0
        sim_red    = 0.0
        if sim_res:
            if isinstance(sim_res, dict):
                sim_before = sim_res["before"]["mean"]
                sim_after  = sim_res["after"]["mean"]
                sim_red    = sim_res["risk_reduction_pct"]
            else:
                sim_before = sim_res.before_remediation.mean
                sim_after  = sim_res.after_remediation.mean
                sim_red    = sim_res.risk_reduction_percentage

        st.markdown(
            f"""
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                        padding:16px 18px;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px;">
                    Analysis Context
                </div>
                <div style="font-size:12px;color:#6b8299;line-height:2.1;">
                    Issues: <span style="color:#3b8ef3;">{n_issues}</span><br>
                    Critical: <span style="color:#f04f47;">{n_critical}</span><br>
                    Fixes: <span style="color:#3dba6e;">{len(fixes)}</span><br>
                    Risk Before: <span style="color:#e88c3a;">{sim_before:.1f}</span><br>
                    Risk After: <span style="color:#3dba6e;">{sim_after:.1f}</span><br>
                    Reduction: <span style="color:#26d4d4;">{sim_red:.1f}%</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("<br>", unsafe_allow_html=True)

        # Background selector
        bg = st.selectbox(
            "User Background",
            ["junior_dev", "manager", "security_expert"],
            format_func=lambda x: {"junior_dev":"🎓 Junior Dev","manager":"💼 Manager",
                                    "security_expert":"🔐 Security Expert"}[x],
            index=["junior_dev","manager","security_expert"].index(
                st.session_state.user_background),
        )
        st.session_state.user_background = bg

        # Clear chat
        if st.button("🗑️ Clear Chat", use_container_width=True):
            st.session_state.chat_history = []
            st.rerun()

        # Suggested questions
        st.markdown(
            '<div style="font-size:10px;color:#3d5166;font-family:\'JetBrains Mono\',monospace;'
            'text-transform:uppercase;letter-spacing:0.1em;margin:12px 0 8px;">Suggested</div>',
            unsafe_allow_html=True,
        )
        suggested = [
            "Why is this critical?",
            "How do I fix the password issue?",
            "Explain the Monte Carlo result",
            "Which issue to fix first?",
        ]
        for q in suggested:
            if st.button(q, use_container_width=True, key=f"sugg_{q}"):
                st.session_state.chat_history.append({"role":"user","content":q})
                # Will be processed below

    with col_chat:
        # Chat history display
        for msg in st.session_state.chat_history:
            with st.chat_message(msg["role"]):
                st.markdown(msg["content"])

        # Input
        user_input = st.chat_input("Ask about your analysis results...")

        if user_input:
            st.session_state.chat_history.append({"role":"user","content":user_input})

            with st.chat_message("user"):
                st.markdown(user_input)

            # Build context for LLM
            context_summary = {
                "file_name":     st.session_state.get("file_name","unknown"),
                "total_issues":  n_issues,
                "critical_count":n_critical,
                "risk_before":   sim_before,
                "risk_after":    sim_after,
                "risk_reduction":sim_red,
                "user_background": st.session_state.user_background,
                "top_issues": [
                    {"rule_id": _get(i,"rule_id",""), "title": _get(i,"title",""),
                     "severity": _get(i,"severity",""), "category": _get(i,"category","")}
                    for i in issues[:5]
                ],
            }

            with st.chat_message("assistant"):
                with st.spinner("Thinking..."):
                    try:
                        from src.core.explainer.llm_explainer import LLMExplainerService

                        api_key = st.session_state.llm_api_key
                        if not api_key:
                            st.error("No API key configured. Add your OpenAI key in the sidebar.")
                            response = "Please configure your OpenAI API key in the sidebar to use this feature."
                        else:
                            explainer = LLMExplainerService(api_key=api_key, enabled=True)
                            response = explainer.explain(
                                report_context=context_summary,
                                user_query=user_input,
                                user_background=st.session_state.get("user_background", "junior_dev"),
                            )

                    except Exception as exc:
                        # Fallback deterministic explanation
                        query_lower = user_input.lower()
                        if "critical" in query_lower or "severe" in query_lower:
                            response = (
                                f"Based on the analysis of **{st.session_state.get('file_name','the config')}**, "
                                f"there are **{n_critical} critical** issues out of {n_issues} total. "
                                f"Critical issues (like hard-coded credentials) represent direct, immediately "
                                f"exploitable vulnerabilities with high confidentiality impact. "
                                f"These should be remediated within 24 hours.\n\n"
                                f"*(Note: LLM unavailable — showing deterministic explanation)*"
                            )
                        elif "fix" in query_lower or "remediat" in query_lower or "how" in query_lower:
                            response = (
                                f"The Blue Team has generated **{len(fixes)} fixes**. "
                                f"Start with the automated fixes (marked 🤖) as they require minimal effort. "
                                f"For credential issues: replace hard-coded values with environment variable "
                                f"references like `${{VAR_NAME}}`. Then restart your service with the "
                                f"variables set in your deployment environment.\n\n"
                                f"*(Note: LLM unavailable — showing deterministic explanation)*"
                            )
                        elif "monte carlo" in query_lower or "risk" in query_lower or "simulation" in query_lower:
                            response = (
                                f"The Monte Carlo simulation ran **{result['iterations'] if isinstance(st.session_state.simulation_result,dict) else 'N'} iterations** "
                                f"sampling from Beta distributions for each issue's likelihood. "
                                f"Results show risk reduced from **{sim_before:.1f}** to **{sim_after:.1f}** "
                                f"({sim_red:.1f}% reduction). The confidence interval provides a range of "
                                f"plausible outcomes, accounting for uncertainty in exploitability estimates.\n\n"
                                f"*(Note: LLM unavailable — showing deterministic explanation)*"
                            )
                        else:
                            response = (
                                f"I can explain the security analysis results for "
                                f"**{st.session_state.get('file_name','your config')}**. "
                                f"The analysis found {n_issues} issues with {n_critical} critical severity. "
                                f"The Monte Carlo simulation projects a {sim_red:.1f}% risk reduction after "
                                f"applying the recommended fixes. Ask me about specific issues, the simulation "
                                f"methodology, or remediation steps.\n\n"
                                f"*(Note: LLM unavailable — showing deterministic explanation)*"
                            )

                    st.markdown(response)
                    st.session_state.chat_history.append({"role":"assistant","content":response})