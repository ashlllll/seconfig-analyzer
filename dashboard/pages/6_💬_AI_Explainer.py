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

st.set_page_config(
    page_title="AI Explainer — SecConfig",
    page_icon="💬",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

for key, val in [
    ("llm_enabled",       False),
    ("llm_backend",       "ollama"),
    ("llm_api_key",       ""),
    ("llm_model",         "llama3.2:1b"),
    ("llm_ollama_url",    "http://localhost:11434"),
    ("chat_history",      []),
    ("issues",            []),
    ("fixes",             []),
    ("simulation_result", None),
    ("user_background",   "junior_dev"),
]:
    if key not in st.session_state:
        st.session_state[key] = val

render_sidebar(current_page="AI Explainer")

# ── Imports ───────────────────────────────────────────────────────────────────
try:
    from src.core.explainer.llm_explainer import (
        LLMExplainerService,
        check_ollama_status,
        OLLAMA_DEFAULT_URL,
    )
    _SERVICE_AVAILABLE = True
except ImportError:
    _SERVICE_AVAILABLE = False

    def check_ollama_status(url="http://localhost:11434"):
        try:
            import requests
            r = requests.get(f"{url}/api/tags", timeout=3)
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                return True, f"Ollama running · {len(models)} model(s) available"
            return False, f"HTTP {r.status_code}"
        except Exception as e:
            return False, str(e)

    OLLAMA_DEFAULT_URL = "http://localhost:11434"


def _get(o, k, d=""):
    return o.get(k, d) if isinstance(o, dict) else getattr(o, k, d)


# ── Header ────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;
                   color:#c9d8e8;margin:0;">💬 AI Explainer</h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Optional LLM layer · Post-analysis explanation only ·
            Does not influence security decisions
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div style="background:#101820;border:1px solid #1e3650;border-radius:8px;
                padding:14px 20px;margin-bottom:20px;border-left:3px solid #3b8ef3;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.08em;margin-bottom:6px;">
            Architecture note
        </div>
        <div style="font-size:13px;color:#6b8299;">
            The LLM is <strong style="color:#c9d8e8;">strictly isolated</strong> as a
            post-analysis explanation module. It receives only deterministic results as
            context and <strong style="color:#c9d8e8;">does not participate</strong> in
            detection, remediation, or risk scoring.
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Settings panel ────────────────────────────────────────────────────────────
with st.expander("⚙️  LLM Settings", expanded=True):

    col_toggle, col_backend = st.columns([1, 2])

    with col_toggle:
        # Use key= so Streamlit manages the value in session_state automatically
        st.toggle("Enable LLM Explainer", key="llm_enabled")

    with col_backend:
        backend = st.selectbox(
            "Backend",
            options=["ollama", "openai"],
            index=["ollama", "openai"].index(st.session_state.llm_backend),
            format_func=lambda x: "🏠 Ollama (local, free)" if x == "ollama"
                                   else "☁️ OpenAI (cloud, needs key)",
        )
        st.session_state.llm_backend = backend

    if backend == "ollama":
        col_url, col_model = st.columns(2)
        with col_url:
            ollama_url = st.text_input(
                "Ollama URL",
                value=st.session_state.llm_ollama_url,
                placeholder="http://localhost:11434",
            )
            st.session_state.llm_ollama_url = ollama_url
        with col_model:
            ollama_model = st.text_input(
                "Model name",
                value=st.session_state.llm_model,
                placeholder="llama3.2:1b",
            )
            st.session_state.llm_model = ollama_model

        col_check, col_status = st.columns([1, 3])
        with col_check:
            do_check = st.button("🔍 Check Ollama", use_container_width=True)
        with col_status:
            if do_check:
                ok, msg = check_ollama_status(ollama_url)
                if ok:
                    st.success(f"✅ {msg}")
                else:
                    st.error(f"❌ {msg}")
                    st.code("ollama serve", language="bash")

        st.markdown(
            f"""
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:8px;
                        padding:12px 16px;margin-top:8px;">
                <div style="font-size:12px;color:#6b8299;line-height:2;">
                    1. Download Ollama → <code>https://ollama.com/download</code><br>
                    2. Pull a model → <code>ollama pull {st.session_state.llm_model}</code><br>
                    3. Run <code>ollama serve</code> if not started automatically<br>
                    4. Toggle <strong style="color:#c9d8e8;">Enable LLM Explainer</strong> above
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        col_key, col_model = st.columns(2)
        with col_key:
            api_val = st.text_input(
                "OpenAI API Key",
                value=st.session_state.llm_api_key,
                type="password",
                placeholder="sk-...",
            )
            st.session_state.llm_api_key = api_val
        with col_model:
            oai_model = st.text_input("Model", value=st.session_state.llm_model)
            st.session_state.llm_model = oai_model

# ── Read enabled AFTER the widget has rendered ────────────────────────────────
enabled = st.session_state.llm_enabled

# ── Status badge ──────────────────────────────────────────────────────────────
if enabled:
    if st.session_state.llm_backend == "ollama":
        ok, msg = check_ollama_status(st.session_state.llm_ollama_url)
        colour = "#3dba6e" if ok else "#f04f47"
        status_text = (
            f"{'✅' if ok else '❌'} {msg} · "
            f"model: <code>{st.session_state.llm_model}</code>"
        )
    else:
        has_key = bool(st.session_state.llm_api_key)
        colour  = "#3dba6e" if has_key else "#f04f47"
        status_text = "✅ OpenAI API key configured" if has_key else "❌ No API key"

    st.markdown(
        f"""<div style="background:#101820;border:1px solid {colour}33;
                    border-radius:6px;padding:8px 16px;margin-bottom:16px;
                    font-size:12px;font-family:'JetBrains Mono',monospace;
                    color:{colour};">{status_text}</div>""",
        unsafe_allow_html=True,
    )

# ── Disabled state ────────────────────────────────────────────────────────────
if not enabled:
    col_main, col_side = st.columns([3, 2])
    with col_main:
        st.markdown(
            """
            <div style="text-align:center;padding:50px 20px;">
                <div style="font-size:3rem;margin-bottom:14px;">🤖</div>
                <p style="font-size:15px;color:#6b8299;">LLM Explainer is disabled</p>
                <p style="font-size:13px;color:#3d5166;margin-top:8px;">
                    Toggle <strong>Enable LLM Explainer</strong> above to activate it.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(
            """<div style="background:#0c1118;border:1px solid #1a2838;
                        border-radius:10px;padding:20px 24px;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                            color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;
                            margin-bottom:12px;">Example questions</div>""",
            unsafe_allow_html=True,
        )
        for q in [
            "Why is CRED-001 classified as critical severity?",
            "How do I fix the hard-coded password issue?",
            "Explain the Monte Carlo risk reduction result",
            "Which issue should I fix first and why?",
        ]:
            st.markdown(
                f'<div style="padding:8px 12px;margin:4px 0;background:#101820;'
                f'border:1px solid #1a2838;border-radius:6px;font-size:13px;'
                f'color:#6b8299;">"{q}"</div>',
                unsafe_allow_html=True,
            )
        st.markdown("</div>", unsafe_allow_html=True)

    with col_side:
        st.markdown(
            """
            <div style="background:#0c1118;border:1px solid #1a2838;
                        border-radius:10px;padding:20px;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                            color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;
                            margin-bottom:14px;">Backends</div>
                <div style="margin-bottom:12px;padding:12px;background:#101820;
                            border:1px solid #1a2838;border-radius:8px;">
                    <div style="font-size:13px;color:#3dba6e;font-weight:600;
                                margin-bottom:6px;">🏠 Ollama (recommended)</div>
                    <div style="font-size:12px;color:#6b8299;line-height:1.7;">
                        Runs 100% on your machine<br>
                        Free · No API key · Private<br>
                        <code>ollama pull llama3.2:1b</code>
                    </div>
                </div>
                <div style="padding:12px;background:#101820;
                            border:1px solid #1a2838;border-radius:8px;">
                    <div style="font-size:13px;color:#3b8ef3;font-weight:600;
                                margin-bottom:6px;">☁️ OpenAI</div>
                    <div style="font-size:12px;color:#6b8299;line-height:1.7;">
                        Cloud API · Requires key<br>
                        gpt-4o-mini recommended
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.stop()

# ═══════════════════════════════════════════════════════════════════════════════
# ENABLED STATE — chat interface
# ═══════════════════════════════════════════════════════════════════════════════
issues  = st.session_state.issues
fixes   = st.session_state.fixes
sim_res = st.session_state.simulation_result

n_issues   = len(issues)
n_critical = sum(1 for i in issues if _get(i, "severity", "").lower() == "critical")
sim_before = sim_after = sim_red = 0.0

if sim_res:
    if isinstance(sim_res, dict):
        sim_before = sim_res["before"]["mean"]
        sim_after  = sim_res["after"]["mean"]
        sim_red    = sim_res["risk_reduction_pct"]
    else:
        sim_before = sim_res.before_remediation.mean
        sim_after  = sim_res.after_remediation.mean
        sim_red    = sim_res.risk_reduction_percentage

backend = st.session_state.llm_backend

if _SERVICE_AVAILABLE:
    llm_service = LLMExplainerService(
        enabled=True,
        backend=backend,
        api_key=st.session_state.llm_api_key if backend == "openai" else None,
        ollama_url=st.session_state.llm_ollama_url,
        model=st.session_state.llm_model,
    )
else:
    llm_service = None

col_chat, col_ctx = st.columns([3, 1])

# ── Context sidebar ───────────────────────────────────────────────────────────
with col_ctx:
    st.markdown(
        f"""
        <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                    padding:16px 18px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                        color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;
                        margin-bottom:12px;">Analysis Context</div>
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

    bg = st.selectbox(
        "Explain as if I am a…",
        ["junior_dev", "manager", "security_expert"],
        format_func=lambda x: {
            "junior_dev":      "🎓 Junior Developer",
            "manager":         "💼 Manager",
            "security_expert": "🔐 Security Expert",
        }[x],
        index=["junior_dev", "manager", "security_expert"].index(
            st.session_state.user_background
        ),
    )
    st.session_state.user_background = bg

    badge_col  = "#3dba6e" if backend == "ollama" else "#3b8ef3"
    badge_text = (
        f"🏠 Ollama · {st.session_state.llm_model}"
        if backend == "ollama"
        else f"☁️ OpenAI · {st.session_state.llm_model}"
    )
    st.markdown(
        f'<div style="font-size:10px;font-family:\'JetBrains Mono\',monospace;'
        f'color:{badge_col};background:{badge_col}18;border:1px solid {badge_col}44;'
        f'border-radius:4px;padding:4px 8px;margin-bottom:8px;">{badge_text}</div>',
        unsafe_allow_html=True,
    )

    if st.button("🗑️ Clear Chat", use_container_width=True):
        st.session_state.chat_history = []
        st.rerun()

    st.markdown(
        '<div style="font-size:10px;color:#3d5166;font-family:\'JetBrains Mono\','
        'monospace;text-transform:uppercase;letter-spacing:0.1em;margin:12px 0 8px;">'
        'Suggested</div>',
        unsafe_allow_html=True,
    )
    for q in [
        "Summarise the findings",
        "Why is this critical?",
        "How to fix the password issue?",
        "Explain the Monte Carlo result",
    ]:
        if st.button(q, use_container_width=True, key=f"sugg_{q}"):
            st.session_state.chat_history.append({"role": "user", "content": q})
            st.rerun()

# ── Chat panel ────────────────────────────────────────────────────────────────
with col_chat:
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    pending = (
        st.session_state.chat_history[-1]["content"]
        if st.session_state.chat_history
        and st.session_state.chat_history[-1]["role"] == "user"
        and len(st.session_state.chat_history) % 2 == 1
        else None
    )

    user_input = st.chat_input("Ask about your analysis results…")
    if user_input:
        st.session_state.chat_history.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)
        pending = user_input

    if pending:
        context_summary = {
            "config_file":    st.session_state.get("file_name", "unknown"),
            "total_issues":   n_issues,
            "critical_count": n_critical,
            "risk_score":     sim_before,
            "final_risk":     sim_after,
            "risk_reduction": sim_red,
            "issues_summary": [
                {
                    "rule_id":  _get(i, "rule_id", ""),
                    "title":    _get(i, "title", ""),
                    "severity": _get(i, "severity", ""),
                    "category": _get(i, "category", ""),
                }
                for i in issues[:5]
            ],
        }

        with st.chat_message("assistant"):
            spinner_text = (
                f"Thinking… via Ollama · {st.session_state.llm_model}"
                if backend == "ollama"
                else "Thinking… via OpenAI"
            )
            with st.spinner(spinner_text):
                if llm_service:
                    response = llm_service.explain(
                        report_context=context_summary,
                        user_query=pending,
                        user_background=st.session_state.user_background,
                    )
                else:
                    q = pending.lower()
                    if "fix" in q or "how" in q:
                        response = (
                            f"The Blue Team generated **{len(fixes)} fix(es)**. "
                            "Start with automated fixes (🤖). For credential issues, "
                            "replace hard-coded values with `${VAR_NAME}`.\n\n"
                            "*(deterministic fallback — LLM module not loaded)*"
                        )
                    elif "risk" in q or "monte" in q:
                        response = (
                            f"Risk dropped from **{sim_before:.1f}** to "
                            f"**{sim_after:.1f}** ({sim_red:.1f}% reduction).\n\n"
                            "*(deterministic fallback — LLM module not loaded)*"
                        )
                    else:
                        response = (
                            f"Found **{n_issues}** issues, **{n_critical}** critical. "
                            f"Risk reduction: **{sim_red:.1f}%**.\n\n"
                            "*(deterministic fallback — LLM module not loaded)*"
                        )

            st.markdown(response)
            st.session_state.chat_history.append(
                {"role": "assistant", "content": response}
            )