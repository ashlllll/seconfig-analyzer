"""
pages/7_📋_Reports.py
~~~~~~~~~~~~~~~~~~~~~~
Report generation and export page.
"""

import json
from pathlib import Path
import sys
from datetime import datetime
from typing import Any

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.components.sidebar import render_sidebar

st.set_page_config(
    page_title="Reports — SecConfig",
    page_icon="📋",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

for key, val in [("issues",[]),("fixes",[]),("simulation_result",None),
                  ("file_name",""),("file_type",""),("analysis_ran",False)]:
    if key not in st.session_state:
        st.session_state[key] = val

render_sidebar(current_page="Reports")

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;color:#c9d8e8;margin:0;">
            📋 Analysis Report
        </h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Comprehensive security findings · Export as JSON or Markdown
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

if not st.session_state.issues:
    st.warning("⚠️ No analysis results. Please run at least the Red Team analysis first.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("📤 Upload File"):
            st.switch_page("pages/2_📤_Upload.py")
    with col2:
        if st.button("🔴 Red Team Analysis"):
            st.switch_page("pages/3_🔴_Red_Team.py")
    st.stop()

issues  = st.session_state.issues
fixes   = st.session_state.fixes
sim_res = st.session_state.simulation_result

def _get(o, k, d=""):
    return o.get(k,d) if isinstance(o,dict) else getattr(o,k,d)


def _to_jsonable(value: Any):
    """
    Convert mixed Python / NumPy / model values into JSON-serializable objects.
    """
    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {str(k): _to_jsonable(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_to_jsonable(v) for v in value]

    # NumPy scalars/arrays expose item()/tolist().
    if hasattr(value, "item"):
        try:
            return _to_jsonable(value.item())
        except Exception:
            pass
    if hasattr(value, "tolist"):
        try:
            return _to_jsonable(value.tolist())
        except Exception:
            pass

    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except Exception:
            pass

    if hasattr(value, "to_dict"):
        try:
            return _to_jsonable(value.to_dict())
        except Exception:
            pass

    return str(value)

# ── Build report data ──────────────────────────────────────────────────────────
now = datetime.now()
report_id = f"RPT-{now.strftime('%Y%m%d-%H%M%S')}"

sev_counts = {}
for i in issues:
    sev = _get(i,"severity","info").lower()
    sev_counts[sev] = sev_counts.get(sev,0) + 1

cat_counts = {}
for i in issues:
    cat = _get(i,"category","unknown")
    cat_counts[cat] = cat_counts.get(cat,0) + 1

nist_counts = {}
for i in issues:
    fn = _get(i,"nist_function","UNKNOWN").upper()
    nist_counts[fn] = nist_counts.get(fn,0) + 1

sim_before = sim_after = sim_red = 0.0
p_val = 1.0
is_sig = False
if sim_res:
    if isinstance(sim_res, dict):
        sim_before = sim_res["before"]["mean"]
        sim_after  = sim_res["after"]["mean"]
        sim_red    = sim_res["risk_reduction_pct"]
        p_val      = sim_res["p_value"]
        is_sig     = sim_res["is_significant"]
    else:
        sim_before = sim_res.before_remediation.mean
        sim_after  = sim_res.after_remediation.mean
        sim_red    = sim_res.risk_reduction_percentage
        p_val      = sim_res.p_value
        is_sig     = sim_res.is_significant

auto_fixes = sum(1 for f in fixes if _get(f,"fix_type","") == "automated")
man_fixes  = sum(1 for f in fixes if _get(f,"fix_type","") == "manual")

# ── Executive Summary ──────────────────────────────────────────────────────────
st.markdown(
    f"""
    <div style="background:#0c1118;border:1px solid #1e3650;border-radius:12px;
                padding:24px 28px;margin-bottom:24px;">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;
                    margin-bottom:16px;">
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:6px;">
                    Executive Summary
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:1.2rem;color:#c9d8e8;">
                    {st.session_state.file_name or "Configuration Analysis"}
                </div>
            </div>
            <div style="text-align:right;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;">
                    {report_id}
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                            margin-top:3px;">
                    {now.strftime('%Y-%m-%d %H:%M:%S')}
                </div>
            </div>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-top:16px;">
            <div style="background:#101820;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;">Total Issues</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            color:#3b8ef3;margin:4px 0;">{len(issues)}</div>
            </div>
            <div style="background:#101820;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;">Critical</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            color:#f04f47;margin:4px 0;">{sev_counts.get('critical',0)}</div>
            </div>
            <div style="background:#101820;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;">Risk Reduction</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            color:#3dba6e;margin:4px 0;">{sim_red:.0f}%</div>
            </div>
            <div style="background:#101820;border-radius:8px;padding:14px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;">Auto Fixes</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            color:#26d4d4;margin:4px 0;">{auto_fixes}</div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ── Detailed tabs ──────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Issues Summary", "🔧 Fixes Applied", "📈 Risk Analysis",
    "🗺️ NIST Coverage",  "💡 Recommendations"
])

# Tab 1 — Issues
with tab1:
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**By Severity**")
        import pandas as pd
        sev_df = pd.DataFrame([
            {"Severity": k.capitalize(), "Count": v,
             "Pct": f"{v/max(len(issues),1)*100:.1f}%"}
            for k, v in sorted(sev_counts.items(),
                               key=lambda x: ["critical","high","medium","low","info"].index(x[0])
                               if x[0] in ["critical","high","medium","low","info"] else 99)
        ])
        st.dataframe(sev_df, use_container_width=True, hide_index=True)

    with col_b:
        st.markdown("**By Category**")
        cat_df = pd.DataFrame([
            {"Category": k.replace("_"," ").title(), "Count": v}
            for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])
        ])
        st.dataframe(cat_df, use_container_width=True, hide_index=True)

    from dashboard.components.chart_components import severity_donut, category_bar
    c1, c2 = st.columns(2)
    with c1:
        if sev_counts:
            st.plotly_chart(severity_donut(sev_counts, height=260), use_container_width=True)
    with c2:
        if cat_counts:
            st.plotly_chart(category_bar(cat_counts, height=260), use_container_width=True)

    st.markdown("---")
    st.markdown("**All Issues**")
    issues_data = []
    for issue in issues:
        issues_data.append({
            "Rule ID":    _get(issue,"rule_id",""),
            "Title":      _get(issue,"title",""),
            "Severity":   _get(issue,"severity","").capitalize(),
            "Category":   _get(issue,"category","").replace("_"," ").title(),
            "Line":       _get(issue,"line_number","?"),
            "NIST":       _get(issue,"nist_function",""),
            "CWE":        _get(issue,"cwe_id",""),
        })
    st.dataframe(pd.DataFrame(issues_data), use_container_width=True, hide_index=True)

# Tab 2 — Fixes
with tab2:
    if fixes:
        fixes_data = []
        for fix in fixes:
            fixes_data.append({
                "Fix ID":    _get(fix,"fix_id",""),
                "Issue":     _get(fix,"issue_title",""),
                "Type":      _get(fix,"fix_type","").replace("_"," ").title(),
                "Priority":  _get(fix,"priority","").capitalize(),
                "Effort":    _get(fix,"effort","").capitalize(),
                "Strategy":  _get(fix,"strategy","").replace("_"," ").title(),
                "Validated": "✅" if _get(fix,"validation_status","") == "validated" else "⚠️",
                "Risk ↓":    f"{float(_get(fix,'risk_reduction',0))*100:.0f}%",
            })
        st.dataframe(pd.DataFrame(fixes_data), use_container_width=True, hide_index=True)
    else:
        st.info("No fixes generated yet. Run Blue Team analysis first.")

# Tab 3 — Risk
with tab3:
    if sim_res:
        from dashboard.components.chart_components import mc_histogram, risk_box_plot

        if isinstance(sim_res, dict):
            bd = sim_res["before"]["data"]
            ad = sim_res["after"]["data"]
        else:
            bd = sim_res.before_remediation.distribution
            ad = sim_res.after_remediation.distribution

        st.plotly_chart(
            mc_histogram(bd, ad, sim_before, sim_after, height=320),
            use_container_width=True
        )

        col_r1, col_r2 = st.columns(2)
        with col_r1:
            st.metric("Risk Before Remediation", f"{sim_before:.1f}", delta=None)
            st.metric("Risk After Remediation",  f"{sim_after:.1f}",  delta=None)
        with col_r2:
            st.metric("Absolute Reduction",  f"{sim_before - sim_after:.1f}")
            st.metric("% Reduction",          f"{sim_red:.1f}%")
            sig_text = "Yes (p < 0.05)" if is_sig else f"No (p = {p_val:.4f})"
            st.metric("Statistically Significant", sig_text)
    else:
        st.info("Run Monte Carlo simulation to see risk analysis results.")

# Tab 4 — NIST
with tab4:
    from dashboard.components.chart_components import nist_radar

    col_nc1, col_nc2 = st.columns([2, 3])
    with col_nc1:
        nist_labels = {"IDENTIFY":"🔍","PROTECT":"🛡️","DETECT":"📡","RESPOND":"⚡","RECOVER":"🔄"}
        for fn, count in nist_counts.items():
            icon = nist_labels.get(fn.upper(), "")
            st.markdown(
                f"""
                <div style="background:#101820;border:1px solid #1a2838;border-radius:6px;
                            padding:10px 14px;margin-bottom:6px;display:flex;
                            justify-content:space-between;align-items:center;">
                    <div style="font-family:'JetBrains Mono',monospace;font-size:13px;color:#c9d8e8;">
                        {icon} {fn}
                    </div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:13px;
                                color:#3b8ef3;">{count} issue{'s' if count!=1 else ''}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    with col_nc2:
        if nist_counts:
            st.plotly_chart(nist_radar(nist_counts, height=300), use_container_width=True)

# Tab 5 — Recommendations
with tab5:
    critical_issues = [i for i in issues if _get(i,"severity","").lower() == "critical"]
    high_issues     = [i for i in issues if _get(i,"severity","").lower() == "high"]

    recommendations = []
    if critical_issues:
        recommendations.append({
            "priority": "🔴 IMMEDIATE",
            "colour": "#f04f47",
            "text": f"Remediate {len(critical_issues)} critical issue(s) immediately — "
                    f"especially {_get(critical_issues[0],'title','')}. "
                    f"These represent directly exploitable vulnerabilities.",
        })
    if high_issues:
        recommendations.append({
            "priority": "🟠 HIGH",
            "colour": "#e88c3a",
            "text": f"Address {len(high_issues)} high-severity issue(s) within 48 hours, "
                    f"including {_get(high_issues[0],'title','')}.",
        })
    if auto_fixes:
        recommendations.append({
            "priority": "🤖 QUICK WIN",
            "colour": "#3dba6e",
            "text": f"Apply {auto_fixes} automated fix(es) from the Blue Team results "
                    f"— these require minimal effort and have high impact.",
        })
    if sim_red > 50:
        recommendations.append({
            "priority": "📊 SIMULATION",
            "colour": "#3b8ef3",
            "text": f"Monte Carlo analysis confirms a projected {sim_red:.0f}% risk reduction "
                    f"after remediation (statistically {'significant' if is_sig else 'not significant'}).",
        })
    recommendations.append({
        "priority": "🔄 ONGOING",
        "colour": "#6b8299",
        "text": "Integrate SecConfig analysis into your CI/CD pipeline to catch configuration "
                "regressions before they reach production.",
    })

    for rec in recommendations:
        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                        padding:14px 18px;margin-bottom:8px;border-left:3px solid {rec['colour']};">
                <div style="font-family:'JetBrains Mono',monospace;font-size:11px;
                            color:{rec['colour']};margin-bottom:6px;">{rec['priority']}</div>
                <div style="font-size:13px;color:#c9d8e8;">{rec['text']}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ── Export ─────────────────────────────────────────────────────────────────────
st.markdown("---")
st.markdown("### ⬇ Export")

report_dict = {
    "report_id":     report_id,
    "generated_at":  now.isoformat(),
    "file_name":     st.session_state.file_name,
    "summary": {
        "total_issues":    len(issues),
        "critical":        sev_counts.get("critical", 0),
        "high":            sev_counts.get("high", 0),
        "medium":          sev_counts.get("medium", 0),
        "low":             sev_counts.get("low", 0),
        "total_fixes":     len(fixes),
        "automated_fixes": auto_fixes,
        "risk_before":     round(sim_before, 2),
        "risk_after":      round(sim_after, 2),
        "risk_reduction_pct": round(sim_red, 2),
        "statistically_significant": is_sig,
    },
    "severity_distribution":  sev_counts,
    "category_distribution":  cat_counts,
    "nist_coverage":          nist_counts,
    "issues": [
        {
            "rule_id":   _get(i,"rule_id",""),
            "title":     _get(i,"title",""),
            "severity":  _get(i,"severity",""),
            "category":  _get(i,"category",""),
            "line":      _get(i,"line_number",""),
            "nist":      _get(i,"nist_function",""),
            "cwe":       _get(i,"cwe_id",""),
            "description": _get(i,"description",""),
            "remediation": _get(i,"remediation_hint",""),
        }
        for i in issues
    ],
}

md_report = f"""# SecConfig Analyzer — Security Report

**Report ID:** {report_id}  
**Generated:** {now.strftime('%Y-%m-%d %H:%M:%S')}  
**File:** {st.session_state.file_name}

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Total Issues | {len(issues)} |
| Critical | {sev_counts.get('critical',0)} |
| Risk Before | {sim_before:.1f} |
| Risk After | {sim_after:.1f} |
| Risk Reduction | {sim_red:.1f}% |
| Automated Fixes | {auto_fixes} |

## Issues Found

| Rule | Title | Severity | Category | Line |
|------|-------|----------|----------|------|
""" + "\n".join(
    f"| {_get(i,'rule_id','')} | {_get(i,'title','')} | {_get(i,'severity','').upper()} "
    f"| {_get(i,'category','').replace('_',' ').title()} | {_get(i,'line_number','')} |"
    for i in issues
) + f"""

## NIST CSF Coverage

""" + "\n".join(f"- **{fn}**: {cnt} issue(s)" for fn, cnt in nist_counts.items()) + """

## Recommendations

""" + "\n".join(f"- **{r['priority']}**: {r['text']}" for r in recommendations)

ecol1, ecol2, ecol3 = st.columns(3)
with ecol1:
    report_json = json.dumps(_to_jsonable(report_dict), indent=2, ensure_ascii=False)
    st.download_button(
        "⬇ Download JSON Report",
        data=report_json,
        file_name=f"secconfig_report_{now.strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
        use_container_width=True,
    )
with ecol2:
    st.download_button(
        "⬇ Download Markdown Report",
        data=md_report,
        file_name=f"secconfig_report_{now.strftime('%Y%m%d_%H%M%S')}.md",
        mime="text/markdown",
        use_container_width=True,
    )
with ecol3:
    import pandas as pd
    issues_df = pd.DataFrame([
        {"Rule":_get(i,"rule_id",""),"Title":_get(i,"title",""),
         "Severity":_get(i,"severity",""),"Category":_get(i,"category",""),
         "Line":_get(i,"line_number",""),"NIST":_get(i,"nist_function",""),
         "CWE":_get(i,"cwe_id","")}
        for i in issues
    ])
    st.download_button(
        "⬇ Download Issues CSV",
        data=issues_df.to_csv(index=False),
        file_name=f"secconfig_issues_{now.strftime('%Y%m%d_%H%M%S')}.csv",
        mime="text/csv",
        use_container_width=True,
    )
