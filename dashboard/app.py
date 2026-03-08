"""
dashboard/app.py
~~~~~~~~~~~~~~~~
SecConfig Analyzer — Streamlit Application Entry Point (Enhanced Home Page).

Run with:
    streamlit run dashboard/app.py
"""

from pathlib import Path
import sys

import streamlit as st

project_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(project_root))

from dashboard.components.sidebar import render_sidebar

# ── Page config ───────────────────────────────────────────────────────────────
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
    "config_file":        None,
    "raw_content":        "",
    "file_name":          "",
    "file_type":          "",
    "issues":             [],
    "fixes":              [],
    "selected_fix_ids":   set(),
    "simulation_result":  None,
    "report":             None,
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

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — HERO
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="text-align:center;padding:40px 0 32px;">
        <div style="font-size:4rem;margin-bottom:16px;">🔒</div>
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:2.4rem;
                   color:#c9d8e8;margin:0;letter-spacing:-0.03em;">
            SecConfig Analyzer
        </h1>
        <p style="color:#6b8299;font-size:16px;margin-top:14px;max-width:640px;
                  margin-left:auto;margin-right:auto;line-height:1.7;">
            A Local AI-Augmented <span style="color:#f04f47;">Red Team</span> /
            <span style="color:#3b8ef3;">Blue Team</span> Framework for
            Configuration Security Analysis with
            <span style="color:#3dba6e;">Monte Carlo</span> Risk Simulation
        </p>
        <div style="margin-top:8px;">
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px;
                         color:#3d5166;background:#0c1118;border:1px solid #1a2838;
                         border-radius:4px;padding:3px 10px;margin:0 4px;">
                NIST CSF Aligned
            </span>
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px;
                         color:#3d5166;background:#0c1118;border:1px solid #1a2838;
                         border-radius:4px;padding:3px 10px;margin:0 4px;">
                Local-First
            </span>
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px;
                         color:#3d5166;background:#0c1118;border:1px solid #1a2838;
                         border-radius:4px;padding:3px 10px;margin:0 4px;">
                Deterministic Analysis
            </span>
            <span style="font-family:'JetBrains Mono',monospace;font-size:11px;
                         color:#3d5166;background:#0c1118;border:1px solid #1a2838;
                         border-radius:4px;padding:3px 10px;margin:0 4px;">
                Open Source
            </span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# CTA button
col_l, col_c, col_r = st.columns([2, 1, 2])
with col_c:
    if st.button("🚀  Start Analysis", use_container_width=True):
        st.switch_page("pages/2_📤_Upload.py")

st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — WHY CONFIGURATION SECURITY MATTERS
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            Why It Matters
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            Configuration Errors Are the #1 Cloud Security Risk
        </h2>
        <p style="color:#6b8299;font-size:13px;margin-top:8px;max-width:700px;">
            Misconfigured files — <code>.env</code>, <code>YAML</code>, <code>JSON</code> —
            are behind some of the world's biggest data breaches.
            Yet they are often the most overlooked part of application security.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Stats row
stat_cols = st.columns(4)
stats = [
    ("95%", "of cloud breaches involve misconfiguration", "#f04f47"),
    ("$4.45M", "average cost of a data breach (IBM 2023)", "#e88c3a"),
    ("80%", "of breaches involve compromised credentials", "#d9a83a"),
    ("200 days", "average time to detect a breach", "#3b8ef3"),
]
for col, (val, label, colour) in zip(stat_cols, stats):
    with col:
        st.markdown(
            f"""
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                        padding:20px 16px;text-align:center;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:2rem;
                            font-weight:700;color:{colour};margin-bottom:8px;">
                    {val}
                </div>
                <div style="font-size:12px;color:#6b8299;line-height:1.5;">
                    {label}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<br>", unsafe_allow_html=True)

# Real-world breach callout — image + text
breach_img_path = Path(__file__).parent / "assets" / "breach_capital.png"
col_breach_img, col_breach_text = st.columns([1, 2], gap="large")

with col_breach_img:
    if breach_img_path.exists():
        st.image(str(breach_img_path), use_container_width=True)

with col_breach_text:
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #1e3650;border-left:3px solid #f04f47;
                    border-radius:8px;padding:18px 22px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#f04f47;
                        text-transform:uppercase;letter-spacing:0.08em;margin-bottom:14px;">
                Real-World Breach Examples
            </div>
            <div style="margin-bottom:14px;">
                <div style="font-size:13px;color:#c9d8e8;font-weight:600;margin-bottom:4px;">
                    🏦 Capital One (2019)
                </div>
                <div style="font-size:12px;color:#6b8299;line-height:1.7;">
                    Misconfigured AWS metadata endpoint exposed IAM credentials.
                    <span style="color:#f04f47;">106 million customers</span> affected. $80M regulatory fine.
                </div>
            </div>
            <div style="margin-bottom:14px;">
                <div style="font-size:13px;color:#c9d8e8;font-weight:600;margin-bottom:4px;">
                    🚗 Toyota (2023)
                </div>
                <div style="font-size:12px;color:#6b8299;line-height:1.7;">
                    An API key was accidentally committed to a public GitHub repository.
                    <span style="color:#f04f47;">2.15 million customers'</span> data was exposed for 5 years undetected.
                </div>
            </div>
            <div>
                <div style="font-size:13px;color:#c9d8e8;font-weight:600;margin-bottom:4px;">
                    🚖 Uber (2022)
                </div>
                <div style="font-size:12px;color:#6b8299;line-height:1.7;">
                    Hard-coded credentials in internal scripts gave an attacker full access to
                    <span style="color:#f04f47;">internal network and source code</span>.
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — COMMON VULNERABILITY TYPES
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            What We Detect
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            5 Categories of Configuration Vulnerabilities
        </h2>
        <p style="color:#6b8299;font-size:13px;margin-top:8px;">
            SecConfig Analyzer covers <strong style="color:#c9d8e8;">23 rules</strong> across
            these five critical security categories.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

# Credentials highlight — image + code example
vuln_cred_img = Path(__file__).parent / "assets" / "vuln_credentials.png"
col_vi, col_vt = st.columns([1, 2], gap="large")
with col_vi:
    if vuln_cred_img.exists():
        st.image(str(vuln_cred_img), use_container_width=True)
with col_vt:
    st.markdown(
        """
        <div style="padding:8px 0;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:13px;
                        color:#f04f47;font-weight:600;margin-bottom:10px;">
                🔑 The Most Common Vulnerability: Hard-coded Credentials
            </div>
            <div style="font-size:13px;color:#6b8299;line-height:1.9;">
                Developers often paste passwords or API keys directly into config files
                during development — and forget to remove them before deploying.
                These files end up in version control, Docker images, or cloud storage,
                making them trivially discoverable by attackers.
            </div>
            <div style="margin-top:14px;font-family:'JetBrains Mono',monospace;
                        font-size:11px;background:#060d14;border:1px solid #1a2838;
                        border-radius:6px;padding:12px 14px;color:#6b8299;">
                <span style="color:#3d5166;"># ❌ What attackers love to find:</span><br>
                DATABASE_PASSWORD=<span style="color:#f04f47;">admin123</span><br>
                STRIPE_API_KEY=<span style="color:#f04f47;">sk_live_abc123xyz</span><br><br>
                <span style="color:#3d5166;"># ✅ What SecConfig Analyzer fixes it to:</span><br>
                DATABASE_PASSWORD=<span style="color:#3dba6e;">${DATABASE_PASSWORD}</span><br>
                STRIPE_API_KEY=<span style="color:#3dba6e;">${STRIPE_API_KEY}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

vuln_cols = st.columns(5)
vulns = [
    (
        "🔑", "Credentials", "#f04f47",
        "5 rules",
        "Hard-coded passwords, API keys, tokens, and secrets embedded directly in config files.",
        ["Hard-coded password", "Exposed API key", "Plain-text DB credentials"],
    ),
    (
        "🔐", "Encryption", "#26d4d4",
        "5 rules",
        "Weak algorithms, missing TLS enforcement, insecure cipher suites, and disabled HTTPS.",
        ["MD5/SHA1 usage", "TLS disabled", "Weak cipher suite"],
    ),
    (
        "🚪", "Access Control", "#e88c3a",
        "5 rules",
        "Overly permissive CORS, open network ports, missing authentication, and wildcard origins.",
        ["CORS wildcard (*)", "Open debug port", "Auth disabled"],
    ),
    (
        "📋", "Logging", "#3dba6e",
        "3 rules",
        "Disabled logging, sensitive data in logs, missing audit trails that hide attacker activity.",
        ["Logging disabled", "Passwords in logs", "No audit trail"],
    ),
    (
        "⚙️", "Baseline", "#3b8ef3",
        "5 rules",
        "Debug mode enabled, insecure defaults, missing security headers, and development settings in production.",
        ["Debug mode ON", "Weak CSP header", "Dev env in prod"],
    ),
]

for col, (icon, name, colour, count, desc, examples) in zip(vuln_cols, vulns):
    with col:
        examples_html = "".join(
            f'<div style="font-size:10px;color:#3d5166;font-family:\'JetBrains Mono\',monospace;'
            f'padding:2px 0;border-bottom:1px solid #0c1118;">{e}</div>'
            for e in examples
        )
        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:10px;
                        padding:18px 14px;height:100%;">
                <div style="font-size:1.8rem;margin-bottom:10px;">{icon}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:13px;
                            font-weight:600;color:{colour};margin-bottom:4px;">
                    {name}
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;
                            color:#3d5166;margin-bottom:10px;">
                    {count}
                </div>
                <div style="font-size:11px;color:#6b8299;line-height:1.6;margin-bottom:12px;">
                    {desc}
                </div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:9px;
                            color:#3d5166;text-transform:uppercase;letter-spacing:0.08em;
                            margin-bottom:6px;">
                    Examples
                </div>
                {examples_html}
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — RED TEAM vs BLUE TEAM
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            Core Architecture
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            Red Team / Blue Team — Separation of Concerns
        </h2>
        <p style="color:#6b8299;font-size:13px;margin-top:8px;max-width:700px;">
            Borrowed from real-world cybersecurity practice, our architecture separates
            <em>attack</em> (finding vulnerabilities) from <em>defence</em> (fixing them).
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

col_red, col_vs, col_blue = st.columns([5, 1, 5])

with col_red:
    redteam_img = Path(__file__).parent / "assets" / "redteam_attacker.png"
    if redteam_img.exists():
        st.image(str(redteam_img), use_container_width=True)
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #f04f4730;border-radius:10px;
                    padding:24px 20px;">
            <div style="display:flex;align-items:center;margin-bottom:16px;">
                <div style="font-size:1.8rem;margin-right:12px;">🔴</div>
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:14px;
                                font-weight:600;color:#f04f47;">Red Team</div>
                    <div style="font-size:11px;color:#3d5166;">Attacker Perspective</div>
                </div>
            </div>
            <div style="font-size:13px;color:#6b8299;line-height:1.8;margin-bottom:16px;">
                In the real world, a <strong style="color:#c9d8e8;">Red Team</strong> simulates
                attackers — probing systems for weaknesses before real adversaries do.
            </div>
            <div style="font-size:13px;color:#6b8299;line-height:1.8;margin-bottom:16px;">
                In SecConfig Analyzer, the Red Team engine applies
                <strong style="color:#c9d8e8;">23 deterministic rules</strong> to scan your
                configuration files, identifying vulnerabilities with exact line numbers and
                severity ratings.
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                        text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">
                How it works
            </div>
            <div style="font-size:12px;color:#6b8299;line-height:2;">
                ① Load 23 YAML-defined security rules<br>
                ② Apply regex pattern matching line-by-line<br>
                ③ Flag matches with severity + CWE mapping<br>
                ④ Generate <code>SecurityIssue</code> objects<br>
                ⑤ Return ranked list (Critical → Info)
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_vs:
    st.markdown(
        """
        <div style="display:flex;align-items:center;justify-content:center;
                    height:100%;min-height:400px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:20px;
                        color:red;font-weight:700;letter-spacing:0.1em;">VS</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_blue:
    blueteam_img = Path(__file__).parent / "assets" / "blueteam_defender.png"
    if blueteam_img.exists():
        st.image(str(blueteam_img), use_container_width=True)
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #3b8ef330;border-radius:10px;
                    padding:24px 20px;">
            <div style="display:flex;align-items:center;margin-bottom:16px;">
                <div style="font-size:1.8rem;margin-right:12px;">🔵</div>
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:14px;
                                font-weight:600;color:#3b8ef3;">Blue Team</div>
                    <div style="font-size:11px;color:#3d5166;">Defender Perspective</div>
                </div>
            </div>
            <div style="font-size:13px;color:#6b8299;line-height:1.8;margin-bottom:16px;">
                A <strong style="color:#c9d8e8;">Blue Team</strong> defends systems —
                responding to findings with concrete fixes and hardening strategies.
            </div>
            <div style="font-size:13px;color:#6b8299;line-height:1.8;margin-bottom:16px;">
                Our Blue Team engine maps each vulnerability to a
                <strong style="color:#c9d8e8;">fix template</strong>, generates corrected
                configuration code, validates it, and shows a side-by-side diff.
            </div>
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                        text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">
                How it works
            </div>
            <div style="font-size:12px;color:#6b8299;line-height:2;">
                ① Receive <code>SecurityIssue</code> list from Red Team<br>
                ② Match each issue to a YAML fix template<br>
                ③ Render corrected configuration code<br>
                ④ Validate fix syntax &amp; security<br>
                ⑤ Show Before / After code diff
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — MONTE CARLO EXPLAINED
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            Risk Quantification
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            What is Monte Carlo Simulation?
        </h2>
        <p style="color:#6b8299;font-size:13px;margin-top:8px;max-width:700px;">
            Most security tools give you a fixed score. We use probability to answer:
            <em>"What's the realistic range of risk, and how much does fixing actually help?"</em>
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

col_mc_left, col_mc_right = st.columns([3, 2], gap="large")

with col_mc_left:
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                    padding:24px 20px;">
            <div style="font-size:13px;color:#6b8299;line-height:1.9;margin-bottom:20px;">
                <strong style="color:#c9d8e8;">Monte Carlo simulation</strong> is a mathematical
                technique that runs thousands of random experiments to model uncertainty.
                Named after the famous casino in Monaco, it uses randomness to solve
                deterministic problems.
            </div>
            <div style="font-size:13px;color:#6b8299;line-height:1.9;margin-bottom:20px;">
                <strong style="color:#3dba6e;">In SecConfig Analyzer:</strong> each security
                issue has a <em>likelihood</em> of exploitation modelled as a
                <strong style="color:#c9d8e8;">Beta distribution</strong>. We run
                <strong style="color:#c9d8e8;">10,000 iterations</strong>, sampling from these
                distributions each time, to produce a realistic risk range — not just a
                single number.
            </div>
            <div style="background:#060d14;border:1px solid #1a2838;border-radius:6px;
                        padding:14px 16px;font-family:'JetBrains Mono',monospace;
                        font-size:12px;color:#6b8299;">
                <span style="color:#3d5166;"># Risk formula per iteration</span><br>
                Risk = Severity × Exploitability<br>
                &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;× Impact_Factor<br>
                &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;× <span style="color:#3dba6e;">Beta.sample(α, β)</span><br><br>
                <span style="color:#3d5166;"># Run 10,000 times → distribution</span><br>
                Total_Risk = <span style="color:#26d4d4;">normalize</span>(Σ risks) × 100
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col_mc_right:
    mc_points = [
        ("📊", "Uncertainty Modelling", "Captures the fact that not every vulnerability will be exploited — risk is probabilistic, not binary."),
        ("🎯", "Before vs After", "Compares risk distributions before and after remediation to quantify how much safer your config becomes."),
        ("📐", "Statistical Rigour", "Uses Wilcoxon signed-rank test to confirm the risk reduction is statistically significant (p < 0.05)."),
        ("🔁", "Reproducible", "Fixed random seed (42) ensures identical results on every run — science, not magic."),
    ]
    for icon, title, desc in mc_points:
        st.markdown(
            f"""
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:8px;
                        padding:14px 16px;margin-bottom:10px;display:flex;gap:12px;">
                <div style="font-size:1.3rem;flex-shrink:0;">{icon}</div>
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                color:#c9d8e8;font-weight:600;margin-bottom:4px;">
                        {title}
                    </div>
                    <div style="font-size:12px;color:#6b8299;line-height:1.6;">
                        {desc}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — NIST CSF ALIGNMENT
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            Framework Alignment
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            Built on the NIST Cybersecurity Framework
        </h2>
        <p style="color:#6b8299;font-size:13px;margin-top:8px;max-width:700px;">
            Every component maps to one of the five NIST CSF core functions —
            the industry-standard approach to managing cybersecurity risk.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

nist_cols = st.columns(5)
nist_items = [
    ("IDENTIFY", "#3b8ef3", "🔍",
     "Asset discovery",
     "Scans config files to catalogue all sensitive assets: credentials, keys, endpoints, DB connections."),
    ("PROTECT", "#3dba6e", "🛡️",
     "Blue Team fixes",
     "Generates hardened replacement configurations using YAML templates aligned to security best practices."),
    ("DETECT", "#f04f47", "🚨",
     "Red Team engine",
     "23-rule engine identifies vulnerabilities using pattern matching, flagging exact line numbers and CWE IDs."),
    ("RESPOND", "#e88c3a", "📋",
     "Report generation",
     "Produces structured analysis reports with executive summary, issue rankings, and prioritised action items."),
    ("RECOVER", "#26d4d4", "🔄",
     "Apply fixes",
     "Applies validated fixes to restore configuration files to a secure, hardened baseline state."),
]

for col, (func, colour, icon, subtitle, desc) in zip(nist_cols, nist_items):
    with col:
        st.markdown(
            f"""
            <div style="background:#0c1118;border:1px solid #1a2838;border-top:3px solid {colour};
                        border-radius:10px;padding:18px 14px;text-align:center;">
                <div style="font-size:1.5rem;margin-bottom:8px;">{icon}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                            font-weight:700;color:{colour};letter-spacing:0.06em;
                            margin-bottom:4px;">
                    {func}
                </div>
                <div style="font-size:11px;color:#c9d8e8;margin-bottom:10px;
                            font-weight:600;">
                    {subtitle}
                </div>
                <div style="font-size:11px;color:#6b8299;line-height:1.6;text-align:left;">
                    {desc}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — HOW TO USE / WORKFLOW
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown(
    """
    <div style="margin-bottom:24px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            Getting Started
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            How to Use SecConfig Analyzer
        </h2>
    </div>
    """,
    unsafe_allow_html=True,
)

steps = [
    ("01", "📤", "Upload", "#3b8ef3",
     "Upload your <code>.env</code>, <code>.yaml</code>, or <code>.json</code> configuration file. "
     "Only use synthetic or test files — never real production secrets."),
    ("02", "🔴", "Red Team Scan", "#f04f47",
     "The rule engine automatically scans your file against 23 security rules, "
     "detecting vulnerabilities with severity ratings and CWE mappings."),
    ("03", "🔵", "Blue Team Fix", "#3b8ef3",
     "For each vulnerability, the Blue Team generates a corrected version using "
     "fix templates. Review the before/after diff and select fixes to apply."),
    ("04", "📊", "Risk Simulation", "#3dba6e",
     "Run 10,000 Monte Carlo iterations to see your risk distribution before and "
     "after remediation, with statistical confidence intervals."),
    ("05", "📋", "Export Report", "#26d4d4",
     "Download a full analysis report (PDF/JSON) with executive summary, "
     "findings, fixes applied, and risk reduction metrics."),
]

for i, (num, icon, title, colour, desc) in enumerate(steps):
    arrow = "↓" if i < len(steps) - 1 else ""
    st.markdown(
        f"""
        <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                    padding:18px 22px;margin-bottom:4px;display:flex;gap:18px;align-items:flex-start;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:1.4rem;
                        color:#1e3650;font-weight:700;flex-shrink:0;padding-top:2px;">
                {num}
            </div>
            <div style="font-size:1.4rem;flex-shrink:0;">{icon}</div>
            <div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:13px;
                            color:{colour};font-weight:600;margin-bottom:6px;">
                    {title}
                </div>
                <div style="font-size:13px;color:#6b8299;line-height:1.7;">
                    {desc}
                </div>
            </div>
        </div>
        {"<div style='text-align:left;padding-left:62px;color:#1e3650;font-size:18px;margin:2px 0;'>↓</div>" if arrow else ""}
        """,
        unsafe_allow_html=True,
    )

st.markdown("<br>", unsafe_allow_html=True)

# Final CTA
col_l2, col_c2, col_r2 = st.columns([2, 1, 2])
with col_c2:
    if st.button("🚀  Get Started Now", use_container_width=True):
        st.switch_page("pages/2_📤_Upload.py")

# ═══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — DESIGN PRINCIPLES
# ═══════════════════════════════════════════════════════════════════════════════
st.markdown("<hr style='border-color:#1a2838;margin:32px 0;'>", unsafe_allow_html=True)

st.markdown(
    """
    <div style="margin-bottom:20px;">
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3b8ef3;
                    text-transform:uppercase;letter-spacing:0.12em;margin-bottom:8px;">
            Design Principles
        </div>
        <h2 style="font-family:'JetBrains Mono',monospace;font-size:1.5rem;
                   color:#c9d8e8;margin:0;">
            What Makes This Tool Different
        </h2>
    </div>
    """,
    unsafe_allow_html=True,
)

principles = [
    ("🎯", "Deterministic, Not AI-Driven",
     "All security decisions are made by a rule engine — not a language model. "
     "Rules are transparent, auditable YAML files. No black box."),
    ("🏠", "Local-First",
     "Runs entirely on your machine. No cloud, no telemetry, no data leaving your system. "
     "Your config files stay private."),
    ("⚡", "Separation of Concerns",
     "Red Team and Blue Team are fully independent modules. "
     "Detection logic never influences remediation logic — and vice versa."),
    ("📐", "Academically Rigorous",
     "Risk quantification uses Beta distributions and Wilcoxon significance testing — "
     "methods grounded in probability theory."),
    ("🧪", "Synthetic Data Only",
     "The tool is designed for testing with synthetic configs. "
     "No real secrets, no real systems — safe to demo and share."),
    ("🔒", "AI as Explainer Only",
     "The optional LLM layer can only see analysis outputs — never your raw config. "
     "It explains results; it never makes decisions."),
]

pcols = st.columns(3)
for i, (icon, title, desc) in enumerate(principles):
    with pcols[i % 3]:
        st.markdown(
            f"""
            <div style="background:#0c1118;border:1px solid #1a2838;border-radius:8px;
                        padding:16px;margin-bottom:12px;">
                <div style="font-size:1.3rem;margin-bottom:8px;">{icon}</div>
                <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                            color:#c9d8e8;font-weight:600;margin-bottom:6px;">
                    {title}
                </div>
                <div style="font-size:12px;color:#6b8299;line-height:1.6;">{desc}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
