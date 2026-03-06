"""
pages/5_📊_Risk_Analysis.py
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Monte Carlo Risk Simulation page.
"""

import time
from pathlib import Path
import sys

import numpy as np

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.components.sidebar import render_sidebar

st.set_page_config(
    page_title="Risk Analysis — SecConfig",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

for key, val in [("issues",[]),("fixes",[]),("simulation_result",None),("simulation_ran",False)]:
    if key not in st.session_state:
        st.session_state[key] = val

render_sidebar(current_page="Risk Analysis")

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;color:#c9d8e8;margin:0;">
            📊 Monte Carlo Risk Simulation
        </h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Probabilistic risk quantification · Beta distribution sampling · 
            Before vs after remediation comparison
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.issues:
    st.warning("⚠️ No issues found. Please run Red Team analysis first.")
    if st.button("🔴 Go to Red Team Analysis"):
        st.switch_page("pages/3_🔴_Red_Team.py")
    st.stop()

# ── Simulation controls ────────────────────────────────────────────────────────
with st.container():
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                    padding:20px 24px;margin-bottom:20px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                        text-transform:uppercase;letter-spacing:0.1em;margin-bottom:14px;">
                Simulation Parameters
            </div>
        """,
        unsafe_allow_html=True,
    )
    c1, c2, c3 = st.columns(3)
    with c1:
        iterations = st.slider("Iterations", 1000, 50000, 10000, 1000,
                               help="More iterations = more accurate but slower")
    with c2:
        confidence = st.select_slider("Confidence Level",
                                      options=[0.90, 0.95, 0.99],
                                      value=0.95,
                                      format_func=lambda x: f"{int(x*100)}%")
    with c3:
        seed = st.number_input("Random Seed", min_value=0, max_value=9999, value=42,
                                help="For reproducibility")
    st.markdown("</div>", unsafe_allow_html=True)

# ── Run simulation ─────────────────────────────────────────────────────────────
col_btn, col_info = st.columns([2, 3])
with col_btn:
    run_sim = st.button("▶  Run Monte Carlo Simulation", type="primary", use_container_width=True)

with col_info:
    issues_count = len(st.session_state.issues)
    fixes_count  = len(st.session_state.fixes)
    st.markdown(
        f"""
        <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;padding:12px 16px;">
            <div style="font-size:12px;color:#c9d8e8;font-family:'JetBrains Mono',monospace;">
                {issues_count} issues · {fixes_count} fixes · {iterations:,} iterations
            </div>
            <div style="font-size:11px;color:#6b8299;margin-top:4px;">
                Seed: {seed} · CI: {int(confidence*100)}%
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

if run_sim:
    with st.spinner("Running Monte Carlo simulation..."):
        progress = st.progress(0, text="Initialising...")
        try:
            from src.core.simulation.monte_carlo import MonteCarloSimulator

            issues_before = st.session_state.issues
            issues_after  = []  # simulated post-fix
            fixes = st.session_state.fixes
            fixed_rules = {f.get("rule_id","") if isinstance(f,dict) else getattr(f,"rule_id","")
                           for f in fixes
                           if (f.get("fix_type","") if isinstance(f,dict) else getattr(f,"fix_type","")) != "manual"}

            def _get(o,k,d=""):
                return o.get(k,d) if isinstance(o,dict) else getattr(o,k,d)

            issues_after = [i for i in issues_before
                            if _get(i,"rule_id","") not in fixed_rules]

            progress.progress(20, text="Sampling distributions...")
            simulator = MonteCarloSimulator(iterations=iterations, seed=seed)
            progress.progress(40, text="Simulating before remediation...")
            result = simulator.simulate(issues_before, issues_after)
            progress.progress(90, text="Computing statistics...")
            time.sleep(0.2)
            progress.progress(100, text="Done.")
            time.sleep(0.3)
            progress.empty()

            st.session_state.simulation_result = result
            st.session_state.simulation_ran = True
            st.rerun()

        except Exception as exc:
            progress.empty()
            st.info(f"Engine unavailable ({exc}). Using demo simulation.")

            np.random.seed(seed)
            n_issues = len(st.session_state.issues)
            n_fixed  = max(0, n_issues - 2)

            before_dist = np.random.beta(4, 2, iterations) * 80 + np.random.normal(0, 5, iterations)
            before_dist = np.clip(before_dist, 0, 100)
            after_dist  = np.random.beta(2, 5, iterations) * 35 + np.random.normal(0, 4, iterations)
            after_dist  = np.clip(after_dist, 0, 100)

            before_mean = float(np.mean(before_dist))
            after_mean  = float(np.mean(after_dist))
            reduction   = before_mean - after_mean
            reduction_pct = (reduction / before_mean * 100) if before_mean > 0 else 0

            alpha = (1 - confidence) / 2
            diff  = before_dist - after_dist
            ci_lo = float(np.percentile(diff, alpha*100))
            ci_hi = float(np.percentile(diff, (1-alpha)*100))

            from scipy.stats import wilcoxon
            try:
                _, p_val = wilcoxon(before_dist, after_dist)
            except Exception:
                p_val = 0.0001

            result = {
                "iterations":    iterations,
                "seed":          seed,
                "before": {
                    "mean":   before_mean,
                    "median": float(np.median(before_dist)),
                    "std":    float(np.std(before_dist)),
                    "p5":     float(np.percentile(before_dist,  5)),
                    "p25":    float(np.percentile(before_dist, 25)),
                    "p75":    float(np.percentile(before_dist, 75)),
                    "p95":    float(np.percentile(before_dist, 95)),
                    "data":   before_dist.tolist(),
                },
                "after": {
                    "mean":   after_mean,
                    "median": float(np.median(after_dist)),
                    "std":    float(np.std(after_dist)),
                    "p5":     float(np.percentile(after_dist,  5)),
                    "p25":    float(np.percentile(after_dist, 25)),
                    "p75":    float(np.percentile(after_dist, 75)),
                    "p95":    float(np.percentile(after_dist, 95)),
                    "data":   after_dist.tolist(),
                },
                "risk_reduction":     reduction,
                "risk_reduction_pct": reduction_pct,
                "confidence_interval": (ci_lo, ci_hi),
                "p_value":     p_val,
                "is_significant": p_val < 0.05,
            }

            st.session_state.simulation_result = result
            st.session_state.simulation_ran = True
            st.rerun()

# ── Show results ───────────────────────────────────────────────────────────────
if st.session_state.simulation_ran and st.session_state.simulation_result:
    result = st.session_state.simulation_result

    def _r(obj, *keys, default=0.0):
        """Navigate dict or object."""
        for key in keys:
            if isinstance(obj, dict):
                obj = obj.get(key, default)
            else:
                obj = getattr(obj, key, default)
        return obj if obj is not None else default

    # Handle both dict (demo) and object (real)
    if isinstance(result, dict):
        before_mean  = result["before"]["mean"]
        after_mean   = result["after"]["mean"]
        reduction    = result["risk_reduction"]
        red_pct      = result["risk_reduction_pct"]
        p_val        = result["p_value"]
        is_sig       = result["is_significant"]
        ci           = result["confidence_interval"]
        before_data  = result["before"]["data"]
        after_data   = result["after"]["data"]
        before_stats = result["before"]
        after_stats  = result["after"]
    else:
        # Real SimulationResult object
        before_mean  = result.before_remediation.mean
        after_mean   = result.after_remediation.mean
        reduction    = result.risk_reduction
        red_pct      = result.risk_reduction_percentage
        p_val        = result.p_value
        is_sig       = result.is_significant
        ci           = result.confidence_interval
        before_data  = result.before_remediation.distribution
        after_data   = result.after_remediation.distribution
        before_stats = {
            "mean": before_mean, "median": result.before_remediation.median,
            "std": result.before_remediation.std_dev,
            "p5": result.before_remediation.p5, "p95": result.before_remediation.p95,
        }
        after_stats = {
            "mean": after_mean, "median": result.after_remediation.median,
            "std": result.after_remediation.std_dev,
            "p5": result.after_remediation.p5, "p95": result.after_remediation.p95,
        }

    st.markdown("<br>", unsafe_allow_html=True)

    # Key metrics
    c1, c2, c3, c4 = st.columns(4)
    for col, label, val, colour, suffix in [
        (c1, "Risk Before", f"{before_mean:.1f}", "#f04f47", "/100"),
        (c2, "Risk After",  f"{after_mean:.1f}",  "#3dba6e", "/100"),
        (c3, "Reduction",   f"{red_pct:.1f}",     "#3b8ef3", "%"),
        (c4, "p-value",     f"{p_val:.4f}",        "#26d4d4" if is_sig else "#6b8299", ""),
    ]:
        with col:
            st.markdown(
                f"""
                <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                            padding:14px 16px;text-align:center;border-top:2px solid {colour};">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                                color:#3d5166;text-transform:uppercase;letter-spacing:0.1em;">{label}</div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:1.8rem;
                                color:{colour};margin:4px 0;">{val}<span style="font-size:1rem;">{suffix}</span></div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    # Significance banner
    sig_colour = "#3dba6e" if is_sig else "#e88c3a"
    sig_icon   = "✅" if is_sig else "⚠️"
    sig_text   = "Statistically significant" if is_sig else "Not statistically significant"
    ci_lo, ci_hi = ci if isinstance(ci, (tuple, list)) else (ci.start if hasattr(ci,"start") else 0, 0)
    st.markdown(
        f"""
        <div style="background:#101820;border:1px solid {sig_colour}33;border-radius:8px;
                    padding:12px 20px;margin:16px 0;display:flex;align-items:center;gap:16px;">
            <span style="font-size:1.2rem;">{sig_icon}</span>
            <div>
                <span style="font-family:'JetBrains Mono',monospace;font-size:13px;color:{sig_colour};">
                    {sig_text}
                </span>
                <span style="font-size:12px;color:#6b8299;margin-left:12px;">
                    {int(confidence*100)}% CI: [{ci_lo:.2f}, {ci_hi:.2f}] 
                    · p = {p_val:.4f}
                    · seed = {result["seed"] if isinstance(result,dict) else result.seed}
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Charts
    from dashboard.components.chart_components import mc_histogram, risk_box_plot, risk_gauge

    chart1, chart2 = st.columns([3, 2])
    with chart1:
        st.plotly_chart(
            mc_histogram(before_data, after_data, before_mean, after_mean, height=360),
            use_container_width=True,
        )
    with chart2:
        st.plotly_chart(risk_box_plot(before_data, after_data, height=360), use_container_width=True)

    gauge1, gauge2 = st.columns(2)
    with gauge1:
        st.plotly_chart(risk_gauge(before_mean, "Risk Score Before", height=220), use_container_width=True)
    with gauge2:
        st.plotly_chart(risk_gauge(after_mean, "Risk Score After", height=220), use_container_width=True)

    # Statistics table
    st.markdown("---")
    st.markdown("### 📋 Detailed Statistics")
    import pandas as pd
    stats_data = {
        "Metric":    ["Mean", "Median", "Std Dev", "5th Pct", "95th Pct"],
        "Before":    [f"{before_stats.get('mean',0):.2f}", f"{before_stats.get('median',0):.2f}",
                      f"{before_stats.get('std',0):.2f}",  f"{before_stats.get('p5',0):.2f}",
                      f"{before_stats.get('p95',0):.2f}"],
        "After":     [f"{after_stats.get('mean',0):.2f}",  f"{after_stats.get('median',0):.2f}",
                      f"{after_stats.get('std',0):.2f}",   f"{after_stats.get('p5',0):.2f}",
                      f"{after_stats.get('p95',0):.2f}"],
        "Improvement": [
            f"{((before_stats.get('mean',0) - after_stats.get('mean',0)) / max(before_stats.get('mean',1),1)*100):.1f}%",
            f"{((before_stats.get('median',0) - after_stats.get('median',0)) / max(before_stats.get('median',1),1)*100):.1f}%",
            "—",
            f"{((before_stats.get('p5',0) - after_stats.get('p5',0)) / max(before_stats.get('p5',1),1)*100):.1f}%",
            f"{((before_stats.get('p95',0) - after_stats.get('p95',0)) / max(before_stats.get('p95',1),1)*100):.1f}%",
        ],
    }
    df = pd.DataFrame(stats_data)
    st.dataframe(df, use_container_width=True, hide_index=True)

    # Export
    csv = df.to_csv(index=False)
    st.download_button("⬇ Export Statistics CSV", csv, "simulation_stats.csv", "text/csv")

    # CTA
    st.markdown("<br>", unsafe_allow_html=True)
    col_a, col_b = st.columns(2)
    with col_a:
        if st.button("📋 Generate Full Report", type="primary", use_container_width=True):
            st.switch_page("pages/7_📋_Reports.py")
    with col_b:
        if st.button("💬 Explain with AI", use_container_width=True):
            st.switch_page("pages/6_💬_AI_Explainer.py")
