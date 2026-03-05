# Templates Catalog

This directory contains the fix template definitions for the Blue Team remediation engine.
Each YAML file corresponds to a category of security issues and maps to the rules in `data/rules_catalog/`.

## Files

| File | Templates | Applies To Rules |
|------|-----------|-----------------|
| `credential_templates.yaml` | CRED-FIX-001 to CRED-FIX-005 | CRED-001 to CRED-005 |
| `encryption_templates.yaml` | ENC-FIX-001 to ENC-FIX-005 | ENC-001 to ENC-005 |
| `access_control_templates.yaml` | AC-FIX-001 to AC-FIX-005 | AC-001 to AC-005 |
| `logging_templates.yaml` | LOG-FIX-001 to LOG-FIX-003 | LOG-001 to LOG-003 |
| `baseline_templates.yaml` | BASE-FIX-001 to BASE-FIX-005 | BASE-001 to BASE-005 |

**Total: 23 fix templates**

## Template Structure

Each template contains:
- `id` — Unique identifier (e.g., CRED-FIX-001)
- `name` — Human-readable name
- `category` — Security category
- `applies_to` — List of rule IDs this template fixes
- `fix_strategy` — How the fix is applied (`template_replacement`, `configuration_change`, `manual_guidance`)
- `fix_template` — The fix pattern with variable placeholders
- `variables` — Variable definitions for the template
- `explanation` — Plain-language explanation of why and how to fix
- `metadata` — Priority, effort, auto-fixable flag
- `side_effects` — Warnings about consequences of applying the fix
- `breaking_change` — Whether the fix may break existing functionality
- `validation` — Rules to verify the fix was applied correctly
- `test_cases` — Input/output examples for testing

## Fix Strategies

- **template_replacement** — Replace the vulnerable value with a template (e.g., env var reference)
- **configuration_change** — Change the value to a secure alternative
- **manual_guidance** — Cannot be auto-fixed; provides step-by-step guidance
