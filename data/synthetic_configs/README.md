# Synthetic Configuration Files

All files in this directory are **synthetic** (artificially created) and contain
no real credentials, keys, or production data. They exist solely for testing
the SecConfig Analyzer rule engine and Blue Team remediation engine.

## Directory Structure

```
synthetic_configs/
├── vulnerable/        # Files with intentional security issues
├── secure/            # Files following security best practices
└── edge_cases/        # Special cases for robustness testing
```

## Vulnerable Configs

| File | Format | Issues Included |
|------|--------|----------------|
| `sample_01.env` | .env | CRED-001~005, ENC-001~003, AC-001~002, LOG-001~002, BASE-001~002 |
| `sample_02.env` | .env | All categories, focus on encryption & access control |
| `sample_03.yaml` | YAML | Nested structure with all categories |
| `sample_04.json` | JSON | Nested JSON with all categories |
| `sample_05.env` | .env | High-sensitivity app (healthcare simulation) |

## Secure Configs

| File | Format | Notes |
|------|--------|-------|
| `best_practice_01.env` | .env | All values use env var references |
| `best_practice_02.yaml` | YAML | Nested YAML following all best practices |
| `best_practice_03.json` | JSON | JSON format with no hardcoded secrets |

## Edge Cases

| File | Purpose |
|------|---------|
| `empty.env` | Parser handles empty file gracefully |
| `comments_only.env` | Only comment lines, no key=value pairs |
| `malformed.yaml` | Invalid YAML syntax — parser error handling |
| `no_issues.env` | Clean file — verifies zero false positives |
| `single_issue.env` | Exactly one issue — precise detection test |
| `large_file.env` | 200+ entries — performance test |
| `mixed_format_issues.json` | JSON with multiple issue categories |

## Usage

These files are used by:
1. **Unit tests** in `tests/unit/` to validate detection accuracy
2. **Integration tests** in `tests/integration/` for end-to-end workflow
3. **Manual testing** via the Streamlit dashboard upload feature
