"""
pages/2_📤_Upload.py
~~~~~~~~~~~~~~~~~~~~~
File upload page — parse and preview configuration files.
"""

from pathlib import Path
import sys

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from dashboard.components.sidebar import render_sidebar


# ── Page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Upload — SecConfig",
    page_icon="📤",
    layout="wide",
    initial_sidebar_state="expanded",
)

css_path = Path(__file__).parent.parent / "styles" / "custom.css"
if css_path.exists():
    st.markdown(f"<style>{open(css_path).read()}</style>", unsafe_allow_html=True)

render_sidebar(current_page="Upload")

# ── Session state guard ────────────────────────────────────────────────────────
for key, val in [("raw_content",""),("file_name",""),("file_type",""),
                  ("config_file",None),("issues",[]),("fixes",[]),
                  ("analysis_ran",False),("fixes_generated",False),
                  ("simulation_ran",False),("simulation_result",None)]:
    if key not in st.session_state:
        st.session_state[key] = val

# ── Header ─────────────────────────────────────────────────────────────────────
st.markdown(
    """
    <div style="margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid #1a2838;">
        <h1 style="font-family:'JetBrains Mono',monospace;font-size:1.6rem;color:#c9d8e8;margin:0;">
            📤 Upload Configuration File
        </h1>
        <p style="color:#6b8299;font-size:13px;margin-top:6px;">
            Supported formats: <code>.env</code> · <code>.yaml</code> / <code>.yml</code> · <code>.json</code>
            &nbsp;|&nbsp; Max size: 10 MB &nbsp;|&nbsp; Synthetic test files only
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

col_left, col_right = st.columns([3, 2], gap="large")

with col_left:
    # ── File uploader ──────────────────────────────────────────────────────────
    uploaded = st.file_uploader(
        "Drop your configuration file here",
        type=["env", "yaml", "yml", "json"],
        help="Only synthetic/test configuration files. No real production data.",
        label_visibility="collapsed",
    )

    if uploaded:
        raw = uploaded.read().decode("utf-8", errors="replace")
        ext = Path(uploaded.name).suffix.lstrip(".").lower()
        if ext == "yml":
            ext = "yaml"

        # Reset downstream state on new file
        if uploaded.name != st.session_state.file_name:
            st.session_state.issues           = []
            st.session_state.fixes            = []
            st.session_state.analysis_ran     = False
            st.session_state.fixes_generated  = False
            st.session_state.simulation_ran   = False
            st.session_state.simulation_result= None
            st.session_state.report           = None

        st.session_state.raw_content = raw
        st.session_state.file_name   = uploaded.name
        st.session_state.file_type   = ext

        # ── File metadata ──────────────────────────────────────────────────────
        lines      = raw.splitlines()
        size_kb    = len(raw.encode()) / 1024
        line_count = len(lines)

        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                        padding:16px 20px;margin:16px 0;">
                <div style="font-family:'JetBrains Mono',monospace;font-size:10px;color:#3d5166;
                            text-transform:uppercase;letter-spacing:0.1em;margin-bottom:10px;">
                    File metadata
                </div>
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;">
                    <div>
                        <div style="font-size:10px;color:#3d5166;margin-bottom:3px;">Name</div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                    color:#26d4d4;">{uploaded.name}</div>
                    </div>
                    <div>
                        <div style="font-size:10px;color:#3d5166;margin-bottom:3px;">Type</div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                    color:#c9d8e8;">.{ext}</div>
                    </div>
                    <div>
                        <div style="font-size:10px;color:#3d5166;margin-bottom:3px;">Size</div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                    color:#c9d8e8;">{size_kb:.1f} KB</div>
                    </div>
                    <div>
                        <div style="font-size:10px;color:#3d5166;margin-bottom:3px;">Lines</div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                    color:#c9d8e8;">{line_count}</div>
                    </div>
                    <div>
                        <div style="font-size:10px;color:#3d5166;margin-bottom:3px;">Encoding</div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                    color:#c9d8e8;">UTF-8</div>
                    </div>
                    <div>
                        <div style="font-size:10px;color:#3d5166;margin-bottom:3px;">Status</div>
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                    color:#3dba6e;">✓ Valid</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # ── File preview ───────────────────────────────────────────────────────
        st.markdown("**Preview** (first 50 lines)")
        preview_lines = lines[:50]
        preview_text  = "\n".join(
            f"{i+1:4d}  {line}" for i, line in enumerate(preview_lines)
        )
        if len(lines) > 50:
            preview_text += f"\n     ... ({len(lines) - 50} more lines)"
        st.code(preview_text, language=ext if ext != "env" else "bash")

        # ── CTA button ─────────────────────────────────────────────────────────
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔴  Run Red Team Analysis", type="primary", use_container_width=True):
            st.switch_page("pages/3_🔴_Red_Team.py")

    else:
        # ── No file uploaded yet ───────────────────────────────────────────────
        st.markdown(
            """
            <div style="text-align:center;padding:60px 20px;color:#3d5166;">
                <div style="font-size:3rem;margin-bottom:12px;">📁</div>
                <p style="font-size:14px;color:#6b8299;">
                    Drag &amp; drop a config file, or click Browse above
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

with col_right:
    # ── Sample file downloads ──────────────────────────────────────────────────
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;padding:20px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                        text-transform:uppercase;letter-spacing:0.1em;margin-bottom:14px;">
                Sample Files
            </div>
            <p style="font-size:13px;color:#6b8299;margin-bottom:16px;">
                Try the analyzer with pre-built synthetic vulnerable configurations.
            </p>
        """,
        unsafe_allow_html=True,
    )

    samples = {
        "sample_vulnerable.env": """# Vulnerable .env sample
DATABASE_URL=postgresql://localhost:5432/mydb
DATABASE_PASSWORD=admin123
SECRET_KEY=my-secret-key-12345
DEBUG=true
CORS_ORIGIN=*
API_KEY=sk-live-abc123xyz789
JWT_SECRET=supersecretjwt
ENCRYPTION_ALGORITHM=MD5
LOG_LEVEL=none
SSL_VERIFY=false""",

        "sample_vulnerable.yaml": """# Vulnerable YAML sample
database:
  host: localhost
  port: 5432
  password: "admin123"
  ssl: false

app:
  debug: true
  secret_key: "hardcoded-secret"
  cors:
    allowed_origins: ["*"]

encryption:
  algorithm: DES
  key_size: 56

logging:
  enabled: false""",

        "sample_secure.env": """# Secure .env example (best practice)
DATABASE_URL=postgresql://localhost:5432/mydb
DATABASE_PASSWORD=${DATABASE_PASSWORD}
SECRET_KEY=${APP_SECRET_KEY}
DEBUG=false
CORS_ORIGIN=https://myapp.example.com
API_KEY=${API_KEY}
JWT_SECRET=${JWT_SECRET}
ENCRYPTION_ALGORITHM=AES-256-GCM
LOG_LEVEL=info
SSL_VERIFY=true""",
    }

    for fname, content in samples.items():
        is_vulnerable = "vulnerable" in fname
        colour = "#f04f47" if is_vulnerable else "#3dba6e"
        label  = "⚠️ Vulnerable" if is_vulnerable else "✅ Secure"
        ext    = fname.split(".")[-1]

        st.markdown(
            f"""
            <div style="background:#101820;border:1px solid #1a2838;border-radius:8px;
                        padding:12px 14px;margin-bottom:8px;display:flex;
                        align-items:center;justify-content:space-between;">
                <div>
                    <div style="font-family:'JetBrains Mono',monospace;font-size:12px;
                                color:#c9d8e8;">{fname}</div>
                    <div style="font-size:11px;color:{colour};margin-top:3px;">{label}</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.download_button(
            label=f"⬇ Download",
            data=content,
            file_name=fname,
            mime="text/plain",
            key=f"dl_{fname}",
            use_container_width=True,
        )

    st.markdown("</div>", unsafe_allow_html=True)

    # Supported formats info
    st.markdown(
        """
        <div style="background:#0c1118;border:1px solid #1a2838;border-radius:10px;
                    padding:20px;margin-top:12px;">
            <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#3d5166;
                        text-transform:uppercase;letter-spacing:0.1em;margin-bottom:12px;">
                Supported Formats
            </div>
            <div style="display:flex;flex-direction:column;gap:8px;">
                <div style="display:flex;align-items:center;gap:10px;">
                    <code style="background:#1a2838;color:#26d4d4;padding:2px 8px;
                                  border-radius:4px;font-size:12px;">.env</code>
                    <span style="font-size:12px;color:#6b8299;">KEY=VALUE environment files</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px;">
                    <code style="background:#1a2838;color:#26d4d4;padding:2px 8px;
                                  border-radius:4px;font-size:12px;">.yaml</code>
                    <span style="font-size:12px;color:#6b8299;">YAML configuration files</span>
                </div>
                <div style="display:flex;align-items:center;gap:10px;">
                    <code style="background:#1a2838;color:#26d4d4;padding:2px 8px;
                                  border-radius:4px;font-size:12px;">.json</code>
                    <span style="font-size:12px;color:#6b8299;">JSON configuration files</span>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
