# 🔒 SecConfig Analyzer

**A Local AI-Augmented Red Team / Blue Team Framework for Configuration Security Analysis with Monte Carlo Risk Simulation**

> BSc (Hons) Cyber Security and Networks — Final Year Project  
> Student: Qian Zhu (S1034134) | Supervisor: Dr. Preethi Kesavan | LSBF Singapore, 2026

---

## 📋 Overview

SecConfig Analyzer is a local configuration security analysis tool that adopts a structured **Red Team / Blue Team** workflow. It combines:

- 🔴 **Red Team** — Deterministic rule-based security review of configuration files
- 🔵 **Blue Team** — Template-based automated remediation
- 📊 **Monte Carlo Simulation** — Probabilistic risk quantification (before vs. after)
- 💬 **AI Explainer** *(optional)* — Natural language explanation for non-expert users

## ✅ Key Design Principles

| Principle | Implementation |
|-----------|---------------|
| Deterministic Analysis | Rule-based engine, no AI in decisions |
| Separation of Concerns | Red Team / Blue Team clearly separated |
| Local-First | Runs entirely on local machine |
| NIST CSF Aligned | IDENTIFY → DETECT → PROTECT → RESPOND → RECOVER |
| Synthetic Data Only | No real production configs used |

## 📁 Supported File Formats

- `.env` — Environment variable files
- `.yaml` / `.yml` — YAML configuration files
- `.json` — JSON configuration files

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/secconfig-analyzer.git
cd secconfig-analyzer

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the application
streamlit run dashboard/app.py
```

## 🏗️ Architecture

```
Upload Config → Parse → Red Team Analysis → Monte Carlo Risk
                                          ↓
                        Blue Team Fixes → Monte Carlo Risk (after)
                                          ↓
                                     Report + AI Explain (optional)
```

## 📊 Project Structure

```
secconfig-analyzer/
├── src/                    # Core source code
│   ├── models/             # Data models (ConfigFile, Issue, Fix, Report)
│   ├── parsers/            # .env / YAML / JSON parsers
│   ├── core/
│   │   ├── red_team/       # Rule-based security analyzer
│   │   ├── blue_team/      # Template-based remediator
│   │   ├── simulation/     # Monte Carlo risk simulator
│   │   └── explainer/      # LLM explanation layer (optional)
│   └── services/           # NIST CSF-aligned service layer
├── dashboard/              # Streamlit frontend
├── data/
│   ├── rules_catalog/      # 23 security rules (YAML)
│   ├── templates_catalog/  # Fix templates (YAML)
│   └── synthetic_configs/  # Test configuration files
└── tests/                  # Unit & integration tests
```

## 🔒 Security Rules Coverage

| Category | Rules | Examples |
|----------|-------|---------|
| Credentials | 5 | Hard-coded passwords, API keys |
| Encryption | 5 | Weak algorithms, missing TLS |
| Access Control | 5 | Permissive CORS, open ports |
| Logging | 3 | Disabled logging, sensitive data in logs |
| Baseline | 5 | Debug mode, insecure defaults |

## ⚠️ Ethical Constraints

- No real production systems or sensitive data involved
- All configuration files analysed are **synthetic**
- Tool does **not** perform attacks or exploit generation
- AI is used **exclusively** for explanation, not security decisions
- Compliant with BCS and Singapore Computer Society codes of conduct

## 📚 References

See full references in the project report (Harvard style).

---

*LSBF Singapore / University of East London — CN6000 Project Module 2025/26*