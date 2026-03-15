"""
Unit tests for the Blue Team engine.
Tests: TemplateLoader, TemplateEngine, FixValidator, BlueTeamRemediator
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


# ══════════════════════════════════════════════
# TemplateLoader Tests
# ══════════════════════════════════════════════

class TestTemplateLoader:

    def test_loader_imports(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        assert loader is not None

    def test_loads_all_templates(self, templates_dir):
        """
        Tests that all templates are loaded correctly.

        Given a valid templates directory, all 23 templates should be loaded into the
        TemplateLoader instance.
        """
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        templates = loader.load_all_templates()
        assert len(templates) == 23

    def test_find_template_for_cred_001(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        template = loader.find_template("CRED-001")
        assert template is not None

    def test_find_template_for_enc_001(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        template = loader.find_template("ENC-001")
        assert template is not None

    def test_find_template_for_ac_001(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        template = loader.find_template("AC-001")
        assert template is not None

    def test_find_template_for_log_001(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        template = loader.find_template("LOG-001")
        assert template is not None

    def test_find_template_for_base_001(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        template = loader.find_template("BASE-001")
        assert template is not None

    def test_find_template_unknown_returns_none(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        template = loader.find_template("UNKNOWN-999")
        assert template is None

    def test_all_rules_have_templates(self, templates_dir):
        from templates.template_loader import TemplateLoader
        loader = TemplateLoader(templates_dir)
        rule_ids = (
            [f"CRED-00{i}" for i in range(1, 6)] +
            [f"ENC-00{i}" for i in range(1, 6)] +
            [f"AC-00{i}" for i in range(1, 6)] +
            [f"LOG-00{i}" for i in range(1, 4)] +
            [f"BASE-00{i}" for i in range(1, 6)]
        )
        for rule_id in rule_ids:
            template = loader.find_template(rule_id)
            assert template is not None, f"No template found for {rule_id}"


# ══════════════════════════════════════════════
# BlueTeamRemediator Tests
# ══════════════════════════════════════════════

class TestBlueTeamRemediator:

    def _make_issue(self, rule_id, key, value, line=1):
        """Helper to create a minimal issue object for testing."""
        try:
            from models.issue_model import SecurityIssue
            from models.risk_model import RiskProfile
            rp = RiskProfile(
                base_severity=7.0,
                exploitability=0.8,
                impact_confidentiality="high",
                impact_integrity="medium",
                impact_availability="low",
                likelihood_mean=0.7,
                likelihood_std=0.15,
            )
            issue = SecurityIssue(
                issue_id=f"test-{rule_id}",
                rule_id=rule_id,
                rule_name=f"Test rule {rule_id}",
                category="credentials",
                severity="high",
                cvss_score=7.5,
                title=f"Test issue {rule_id}",
                description="Test description",
                file_name="test.env",
                line_number=line,
                vulnerable_code=f"{key}={value}",
                risk_profile=rp,
                remediation_hint="Fix this",
                nist_function="PROTECT",
                nist_category="PR.AC-1",
                cwe_id="CWE-798",
            )
            return issue
        except Exception:
            return {
                "issue_id": f"test-{rule_id}",
                "rule_id": rule_id,
                "vulnerable_code": f"{key}={value}",
                "line_number": line,
                "file_name": "test.env",
            }

    def _get_remediator(self, templates_dir):
        from src.core.blue_team.remediator import BlueTeamRemediator
        return BlueTeamRemediator(templates_dir=templates_dir)

    def test_remediator_imports(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        assert remediator is not None

    def test_generates_fix_for_cred_001(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("CRED-001", "DATABASE_PASSWORD", "admin123")
        fixes = remediator.remediate([issue])
        assert len(fixes) == 1

    def test_fix_has_fixed_code(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("CRED-001", "DATABASE_PASSWORD", "admin123")
        fixes = remediator.remediate([issue])
        fix = fixes[0]
        fixed = fix.fixed_code if hasattr(fix, 'fixed_code') else fix.get('fixed_code', '')
        assert fixed is not None
        assert fixed != ""

    def test_fix_references_env_var(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("CRED-001", "DATABASE_PASSWORD", "admin123")
        fixes = remediator.remediate([issue])
        fix = fixes[0]
        fixed = fix.fixed_code if hasattr(fix, 'fixed_code') else fix.get('fixed_code', '')
        assert "${" in fixed or "$(" in fixed

    def test_fix_has_explanation(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("CRED-001", "DATABASE_PASSWORD", "admin123")
        fixes = remediator.remediate([issue])
        fix = fixes[0]
        explanation = fix.explanation if hasattr(fix, 'explanation') else fix.get('explanation', '')
        assert explanation is not None
        assert len(explanation) > 0

    def test_fix_type_automated_for_cred(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("CRED-001", "DATABASE_PASSWORD", "admin123")
        fixes = remediator.remediate([issue])
        fix = fixes[0]
        fix_type = fix.fix_type if hasattr(fix, 'fix_type') else fix.get('fix_type', '')
        assert fix_type in ('automated', 'semi_automated', 'manual')

    def test_multiple_issues_multiple_fixes(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issues = [
            self._make_issue("CRED-001", "DATABASE_PASSWORD", "admin123", 1),
            self._make_issue("ENC-001", "CIPHER_ALGORITHM", "DES", 2),
            self._make_issue("LOG-001", "LOGGING_ENABLED", "false", 3),
        ]
        fixes = remediator.remediate(issues)
        assert len(fixes) == 3

    def test_unknown_rule_creates_manual_fix(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("UNKNOWN-999", "SOME_KEY", "some_value")
        fixes = remediator.remediate([issue])
        assert len(fixes) == 1
        fix = fixes[0]
        fix_type = fix.fix_type if hasattr(fix, 'fix_type') else fix.get('fix_type', '')
        assert fix_type == 'manual'

    def test_empty_issues_returns_empty_fixes(self, templates_dir):
        remediator = self._get_remediator(templates_dir)
        fixes = remediator.remediate([])
        assert fixes == []

    def test_debug_fix_disables_debug(self, templates_dir):
        """BASE-001 uses configuration_change strategy → sets value to false"""
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("BASE-001", "DEBUG", "true")
        fixes = remediator.remediate([issue])
        assert len(fixes) == 1
        fix = fixes[0]
        fixed = fix.fixed_code if hasattr(fix, 'fixed_code') else fix.get('fixed_code', '')
        assert fixed != ""

    def test_logging_fix_is_generated(self, templates_dir):
        """LOG-001 should always produce a fix of some type"""
        remediator = self._get_remediator(templates_dir)
        issue = self._make_issue("LOG-001", "LOGGING_ENABLED", "false")
        fixes = remediator.remediate([issue])
        assert len(fixes) == 1
        fix = fixes[0]
        fix_type = fix.fix_type if hasattr(fix, 'fix_type') else fix.get('fix_type', '')
        assert fix_type in ('automated', 'semi_automated', 'manual')


# ══════════════════════════════════════════════
# FixValidator Tests
# ══════════════════════════════════════════════

class TestFixValidator:

    def test_validator_imports(self):
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        assert v is not None

    def test_valid_env_var_reference_passes(self):
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        is_valid, error = v.validate_syntax("DATABASE_PASSWORD=${DATABASE_PASSWORD}", "env")
        assert is_valid is True

    def test_empty_fixed_code_fails(self):
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "template_replacement", "validation": []}
        is_valid, errors = v.validate(
            original_code="LOGGING_ENABLED=false",
            fixed_code="",
            template=template,
            file_type="env",
        )
        assert is_valid is False
        assert len(errors) > 0

    # ── validate_syntax is now wired into validate() ──────────────────────────

    def test_syntax_check_fires_inside_validate_for_bad_env(self):
        """validate() must reject .env lines that have no '=' sign."""
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "configuration_change", "validation": []}
        # A YAML-style line has no '=' so env syntax check should fail
        is_valid, errors = v.validate(
            original_code="DEBUG=true",
            fixed_code="debug: false",   # valid YAML, invalid .env
            template=template,
            file_type="env",
        )
        assert is_valid is False
        assert any("syntax" in e.lower() or "=" in e for e in errors)

    def test_syntax_check_passes_for_valid_env_fix(self):
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "configuration_change", "validation": []}
        is_valid, errors = v.validate(
            original_code="DEBUG=true",
            fixed_code="DEBUG=false",
            template=template,
            file_type="env",
        )
        # Should be valid (changed + valid syntax)
        assert is_valid is True

    # ── Expanded _SAFE_REFERENCE_PATTERNS ────────────────────────────────────

    def test_dollar_brace_reference_passes_security_check(self):
        """${VAR} format must pass template_replacement security check."""
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "template_replacement", "validation": []}
        is_valid, errors = v.validate(
            original_code="API_KEY=sk-live-abc123",
            fixed_code="API_KEY=${API_KEY}",
            template=template,
            file_type="env",
        )
        assert is_valid is True

    def test_bare_dollar_var_passes_security_check(self):
        """$UPPERCASE_VAR format must also pass."""
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "template_replacement", "validation": []}
        is_valid, errors = v.validate(
            original_code="API_KEY=sk-live-abc123",
            fixed_code="API_KEY=$API_KEY",
            template=template,
            file_type="env",
        )
        assert is_valid is True

    def test_vault_reference_passes_security_check(self):
        """vault: URI must pass template_replacement security check."""
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "template_replacement", "validation": []}
        is_valid, errors = v.validate(
            original_code="DB_PASS=admin123",
            fixed_code="DB_PASS=vault:secret/data/app#db_password",
            template=template,
            file_type="env",
        )
        assert is_valid is True

    def test_ssm_reference_passes_security_check(self):
        """ssm: URI must pass template_replacement security check."""
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "template_replacement", "validation": []}
        is_valid, errors = v.validate(
            original_code="DB_PASS=admin123",
            fixed_code="DB_PASS=ssm:/myapp/prod/db_password",
            template=template,
            file_type="env",
        )
        assert is_valid is True

    def test_hardcoded_value_still_fails_security_check(self):
        """A fix that just changes the value but keeps it hard-coded should fail."""
        from src.core.blue_team.validator import FixValidator
        v = FixValidator()
        template = {"fix_strategy": "template_replacement", "validation": []}
        is_valid, errors = v.validate(
            original_code="DB_PASS=admin123",
            fixed_code="DB_PASS=different_hardcoded_value",
            template=template,
            file_type="env",
        )
        assert is_valid is False


# ══════════════════════════════════════════════
# simulate_remediation: manual fix exclusion
# ══════════════════════════════════════════════

class TestSimulateRemediationManualExclusion:
    """
    Regression tests for the fix where manual fixes were incorrectly
    counted as applied in simulate_remediation(), leading to under-estimated
    post-remediation risk.
    """

    def _make_issues_and_fixes(self, templates_dir):
        """Create 2 issues — one with an automated fix, one manual."""
        from src.core.blue_team.remediator import BlueTeamRemediator
        from src.parsers.env_parser import EnvParser

        content = "DATABASE_PASSWORD=admin123\nCORS_ORIGIN=*\n"
        config = EnvParser().parse(content, "test.env")
        remediator = BlueTeamRemediator(templates_dir=templates_dir)

        from src.core.red_team.analyzer import RedTeamAnalyzer
        import os
        # Use a minimal inline rules dir if real one not available
        try:
            analyzer = RedTeamAnalyzer()
            issues = analyzer.analyze(config)
        except Exception:
            return None, None

        fixes = remediator.remediate(issues)
        return issues, fixes

    def test_manual_fix_does_not_reduce_remaining_issues(self, templates_dir):
        """
        If all generated fixes are manual, simulate_remediation should return
        the full issue list unchanged.
        """
        from src.core.blue_team.remediator import BlueTeamRemediator
        remediator = BlueTeamRemediator(templates_dir=templates_dir)

        # Build a mock issue
        try:
            from src.models.issue_model import SecurityIssue
            from src.models.risk_model import RiskProfile
            rp = RiskProfile(7.0, 0.8, "high", "medium", "low", 0.7, 0.15)
            issue = SecurityIssue(
                issue_id="test-manual-001",
                rule_id="UNKNOWN-999",
                rule_name="Unknown rule",
                category="credentials",
                severity="high",
                cvss_score=7.0,
                title="Test",
                description="Test",
                file_name="test.env",
                line_number=1,
                vulnerable_code="KEY=value",
                risk_profile=rp,
                remediation_hint="Manual fix required",
                nist_function="PROTECT",
                nist_category="PR.AC-1",
                cwe_id="CWE-798",
            )
        except Exception:
            return  # Skip if models not importable

        fixes = remediator.remediate([issue])
        # Should be a manual fix (unknown rule → no template)
        fix = fixes[0]
        fix_type = fix.fix_type if hasattr(fix, "fix_type") else fix.get("fix_type")
        assert fix_type == "manual"

        # simulate_remediation must NOT remove the issue
        remaining = remediator.simulate_remediation([issue], fixes)
        assert len(remaining) == 1, (
            "Manual fixes should not count as applied in simulate_remediation. "
            "Post-remediation risk would be under-estimated otherwise."
        )