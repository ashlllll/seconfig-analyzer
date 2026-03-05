"""
Unit tests for data models.
Tests: ConfigFile, RiskProfile, SecurityIssue, SecurityFix, AnalysisReport
"""

import pytest
import sys
import os
from datetime import datetime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


class TestConfigFileModel:

    def test_config_file_imports(self):
        from models.config_model import ConfigFile
        assert ConfigFile is not None

    def test_create_config_file(self):
        from models.config_model import ConfigFile
        cf = ConfigFile(
            file_name="test.env",
            file_type="env",
            file_path="/tmp/test.env",
            file_size=100,
            upload_timestamp=datetime.now(),
            raw_content="KEY=value\n",
            parsed_content={"KEY": "value"},
        )
        assert cf.file_name == "test.env"
        assert cf.file_type == "env"

    def test_default_is_valid_true(self):
        from models.config_model import ConfigFile
        cf = ConfigFile(
            file_name="test.env",
            file_type="env",
            file_path="/tmp/test.env",
            file_size=0,
            upload_timestamp=datetime.now(),
            raw_content="",
            parsed_content={},
        )
        assert cf.is_valid is True

    def test_default_parse_errors_empty(self):
        from models.config_model import ConfigFile
        cf = ConfigFile(
            file_name="test.env",
            file_type="env",
            file_path="/tmp/test.env",
            file_size=0,
            upload_timestamp=datetime.now(),
            raw_content="",
            parsed_content={},
        )
        assert cf.parse_errors == []


class TestRiskProfileModel:

    def test_risk_profile_imports(self):
        from models.risk_model import RiskProfile
        assert RiskProfile is not None

    def test_create_risk_profile(self):
        from models.risk_model import RiskProfile
        rp = RiskProfile(
            base_severity=7.5,
            exploitability=0.8,
            impact_confidentiality="high",
            impact_integrity="medium",
            impact_availability="low",
            likelihood_mean=0.7,
            likelihood_std=0.15,
        )
        assert rp.base_severity == 7.5
        assert rp.exploitability == 0.8

    def test_default_distribution_type(self):
        from models.risk_model import RiskProfile
        rp = RiskProfile(
            base_severity=5.0,
            exploitability=0.5,
            impact_confidentiality="medium",
            impact_integrity="medium",
            impact_availability="medium",
            likelihood_mean=0.5,
            likelihood_std=0.1,
        )
        assert rp.distribution_type == "beta"


class TestSecurityIssueModel:

    def _make_risk_profile(self):
        from models.risk_model import RiskProfile
        return RiskProfile(
            base_severity=7.0,
            exploitability=0.8,
            impact_confidentiality="high",
            impact_integrity="medium",
            impact_availability="low",
            likelihood_mean=0.7,
            likelihood_std=0.15,
        )

    def test_issue_imports(self):
        from models.issue_model import SecurityIssue
        assert SecurityIssue is not None

    def test_create_issue(self):
        from models.issue_model import SecurityIssue
        issue = SecurityIssue(
            issue_id="test-001",
            rule_id="CRED-001",
            rule_name="Hard-coded Password",
            category="credentials",
            severity="critical",
            cvss_score=9.0,
            title="Hard-coded Password Detected",
            description="Password is hard-coded",
            file_name="test.env",
            line_number=5,
            vulnerable_code="DATABASE_PASSWORD=admin123",
            risk_profile=self._make_risk_profile(),
            remediation_hint="Use environment variable",
            nist_function="PROTECT",
            nist_category="PR.AC-1",
            cwe_id="CWE-798",
        )
        assert issue.rule_id == "CRED-001"
        assert issue.severity == "critical"
        assert issue.line_number == 5

    def test_default_status_detected(self):
        from models.issue_model import SecurityIssue
        issue = SecurityIssue(
            issue_id="test-001",
            rule_id="CRED-001",
            rule_name="Test",
            category="credentials",
            severity="high",
            cvss_score=7.0,
            title="Test",
            description="Test",
            file_name="test.env",
            line_number=1,
            vulnerable_code="KEY=val",
            risk_profile=self._make_risk_profile(),
            remediation_hint="Fix",
            nist_function="PROTECT",
            nist_category="PR.AC-1",
            cwe_id="CWE-798",
        )
        assert issue.status == "detected"

    def test_default_confidence_one(self):
        from models.issue_model import SecurityIssue
        issue = SecurityIssue(
            issue_id="test-001",
            rule_id="CRED-001",
            rule_name="Test",
            category="credentials",
            severity="high",
            cvss_score=7.0,
            title="Test",
            description="Test",
            file_name="test.env",
            line_number=1,
            vulnerable_code="KEY=val",
            risk_profile=self._make_risk_profile(),
            remediation_hint="Fix",
            nist_function="PROTECT",
            nist_category="PR.AC-1",
            cwe_id="CWE-798",
        )
        assert issue.confidence == 1.0


class TestSecurityFixModel:

    def test_fix_imports(self):
        from models.fix_model import SecurityFix
        assert SecurityFix is not None

    def test_create_fix(self):
        from models.fix_model import SecurityFix
        fix = SecurityFix(
            fix_id="fix-001",
            issue_id="issue-001",
            issue_title="Hard-coded Password",
            fix_type="automated",
            template_id="CRED-FIX-001",
            original_code="DATABASE_PASSWORD=admin123",
            fixed_code="DATABASE_PASSWORD=${DATABASE_PASSWORD}",
            explanation="Replace with env var",
            strategy="template_replacement",
            priority="immediate",
            effort="low",
        )
        assert fix.fix_id == "fix-001"
        assert fix.fix_type == "automated"

    def test_default_applied_false(self):
        from models.fix_model import SecurityFix
        fix = SecurityFix(
            fix_id="fix-001",
            issue_id="issue-001",
            issue_title="Test",
            fix_type="automated",
            template_id="CRED-FIX-001",
            original_code="KEY=val",
            fixed_code="KEY=${KEY}",
            explanation="Fix",
            strategy="template_replacement",
            priority="high",
            effort="low",
        )
        assert fix.applied is False

    def test_default_validation_pending(self):
        from models.fix_model import SecurityFix
        fix = SecurityFix(
            fix_id="fix-001",
            issue_id="issue-001",
            issue_title="Test",
            fix_type="automated",
            template_id="CRED-FIX-001",
            original_code="KEY=val",
            fixed_code="KEY=${KEY}",
            explanation="Fix",
            strategy="template_replacement",
            priority="high",
            effort="low",
        )
        assert fix.validation_status == "pending"
