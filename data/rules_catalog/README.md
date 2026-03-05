# Rules Catalog

This directory contains the security rules used by the Red Team analyzer.

## Rule Categories

| File | Category | Count |
|------|----------|-------|
| `credential_rules.yaml` | Credentials (passwords, API keys, tokens) | 5 |
| `encryption_rules.yaml` | Encryption & TLS settings | 5 |
| `access_control_rules.yaml` | Access control & network exposure | 5 |
| `logging_rules.yaml` | Logging & monitoring | 3 |
| `baseline_rules.yaml` | Baseline security settings | 5 |

**Total: 23 rules**

## Rule ID Format

`{CATEGORY}-{NUMBER}` — e.g., `CRED-001`, `ENC-002`, `AC-003`

## Rule Severity Levels

- `critical` — Immediate action required (CVSS 9.0–10.0)
- `high` — High priority (CVSS 7.0–8.9)
- `medium` — Medium priority (CVSS 4.0–6.9)
- `low` — Low priority (CVSS 0.1–3.9)
- `info` — Informational

## NIST CSF Mapping

All rules are mapped to NIST Cybersecurity Framework 2.0 functions and categories.
