"""
Unit tests for the service layer.
Tests: DetectionService, ProtectionService, SimulationService, AnalysisService
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


def _make_config(content="DATABASE_PASSWORD=admin123\nDEBUG=true\n",
                  filename="test.env"):
    from src.parsers.env_parser import EnvParser
    return EnvParser().parse(content, filename)


# ══════════════════════════════════════════════
# DetectionService Tests
# ══════════════════════════════════════════════

class TestDetectionService:

    def test_service_imports(self, rules_dir):
        from src.services.detection_service import DetectionService
        svc = DetectionService(rules_dir=rules_dir)
        assert svc is not None

    def test_detects_issues_in_vulnerable_config(self, rules_dir):
        from src.services.detection_service import DetectionService
        svc = DetectionService(rules_dir=rules_dir)
        config = _make_config()
        issues = svc.detect_vulnerabilities(config)
        assert len(issues) >= 1

    def test_no_issues_in_clean_config(self, rules_dir):
        from src.services.detection_service import DetectionService
        svc = DetectionService(rules_dir=rules_dir)
        config = _make_config("APP_NAME=test\nDEBUG=false\n", "clean.env")
        issues = svc.detect_vulnerabilities(config)
        assert len(issues) == 0

    def test_returns_list(self, rules_dir):
        from src.services.detection_service import DetectionService
        svc = DetectionService(rules_dir=rules_dir)
        config = _make_config()
        result = svc.detect_vulnerabilities(config)
        assert isinstance(result, list)

    def test_issues_sorted_by_severity(self, rules_dir, vulnerable_env_content):
        from src.services.detection_service import DetectionService
        svc = DetectionService(rules_dir=rules_dir)
        from src.parsers.env_parser import EnvParser
        config = EnvParser().parse(vulnerable_env_content, "test.env")
        issues = svc.detect_vulnerabilities(config)
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        severities = [severity_order.get(
            i.severity if hasattr(i, 'severity') else i.get('severity', 'info'), 0
        ) for i in issues]
        assert severities == sorted(severities, reverse=True)


# ══════════════════════════════════════════════
# ProtectionService Tests
# ══════════════════════════════════════════════

class TestProtectionService:

    def test_service_imports(self, templates_dir):
        from src.services.protection_service import ProtectionService
        svc = ProtectionService(templates_dir=templates_dir)
        assert svc is not None

    def test_generates_fixes_for_issues(self, rules_dir, templates_dir):
        from src.services.detection_service import DetectionService
        from src.services.protection_service import ProtectionService
        config = _make_config()
        issues = DetectionService(rules_dir=rules_dir).detect_vulnerabilities(config)
        svc = ProtectionService(templates_dir=templates_dir)
        fixes = svc.generate_fixes(issues)
        assert len(fixes) > 0

    def test_returns_list_of_fixes(self, templates_dir):
        from src.services.protection_service import ProtectionService
        svc = ProtectionService(templates_dir=templates_dir)
        fixes = svc.generate_fixes([])
        assert isinstance(fixes, list)

    def test_empty_issues_empty_fixes(self, templates_dir):
        from src.services.protection_service import ProtectionService
        svc = ProtectionService(templates_dir=templates_dir)
        fixes = svc.generate_fixes([])
        assert fixes == []

    def test_simulate_remediation_removes_fixed(self, rules_dir, templates_dir):
        from src.services.detection_service import DetectionService
        from src.services.protection_service import ProtectionService
        config = _make_config()
        issues = DetectionService(rules_dir=rules_dir).detect_vulnerabilities(config)
        svc = ProtectionService(templates_dir=templates_dir)
        fixes = svc.generate_fixes(issues)
        # Mark all fixes as applied
        for fix in fixes:
            if hasattr(fix, 'applied'):
                fix.applied = True
            elif isinstance(fix, dict):
                fix['applied'] = True
        remaining = svc.simulate_remediation(issues, fixes)
        assert len(remaining) < len(issues)


# ══════════════════════════════════════════════
# SimulationService Tests
# ══════════════════════════════════════════════

class TestSimulationService:

    def test_service_imports(self):
        from src.services.simulation_service import SimulationService
        svc = SimulationService(iterations=100)
        assert svc is not None

    def test_calculate_initial_risk_returns_float(self, rules_dir):
        from src.services.simulation_service import SimulationService
        from src.services.detection_service import DetectionService
        config = _make_config()
        issues = DetectionService(rules_dir=rules_dir).detect_vulnerabilities(config)
        svc = SimulationService(iterations=100)
        risk = svc.calculate_initial_risk(issues)
        assert isinstance(risk, float)
        assert risk >= 0.0

    def test_run_monte_carlo_returns_result(self, rules_dir):
        from src.services.simulation_service import SimulationService
        from src.services.detection_service import DetectionService
        config = _make_config()
        issues = DetectionService(rules_dir=rules_dir).detect_vulnerabilities(config)
        svc = SimulationService(iterations=100)
        result = svc.run_monte_carlo(issues_before=issues, issues_after=[])
        assert result is not None

    def test_zero_issues_zero_risk(self):
        from src.services.simulation_service import SimulationService
        svc = SimulationService(iterations=100)
        risk = svc.calculate_initial_risk([])
        assert risk == 0.0


# ══════════════════════════════════════════════
# AnalysisService Integration Tests
# ══════════════════════════════════════════════

class TestAnalysisService:

    def test_service_imports(self, rules_dir, templates_dir):
        from src.services.analysis_service import AnalysisService
        svc = AnalysisService(
            rules_dir=rules_dir,
            templates_dir=templates_dir,
            simulation_iterations=100
        )
        assert svc is not None

    def test_full_analysis_returns_report(self, rules_dir, templates_dir):
        from src.services.analysis_service import AnalysisService
        svc = AnalysisService(
            rules_dir=rules_dir,
            templates_dir=templates_dir,
            simulation_iterations=100
        )
        config = _make_config()
        report = svc.run_full_analysis(config)
        assert report is not None

    def test_report_has_issues(self, rules_dir, templates_dir):
        from src.services.analysis_service import AnalysisService
        svc = AnalysisService(
            rules_dir=rules_dir,
            templates_dir=templates_dir,
            simulation_iterations=100
        )
        config = _make_config()
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) > 0

    def test_report_has_fixes(self, rules_dir, templates_dir):
        from src.services.analysis_service import AnalysisService
        svc = AnalysisService(
            rules_dir=rules_dir,
            templates_dir=templates_dir,
            simulation_iterations=100
        )
        config = _make_config()
        report = svc.run_full_analysis(config)
        fixes = report.fixes if hasattr(report, 'fixes') else report.get('fixes', [])
        assert fixes is not None

    def test_report_has_risk_scores(self, rules_dir, templates_dir):
        from src.services.analysis_service import AnalysisService
        svc = AnalysisService(
            rules_dir=rules_dir,
            templates_dir=templates_dir,
            simulation_iterations=100
        )
        config = _make_config()
        report = svc.run_full_analysis(config)
        initial = (report.initial_risk_score
                   if hasattr(report, 'initial_risk_score')
                   else report.get('initial_risk_score', -1))
        assert initial >= 0

    def test_clean_config_report_zero_issues(self, rules_dir, templates_dir):
        from src.services.analysis_service import AnalysisService
        svc = AnalysisService(
            rules_dir=rules_dir,
            templates_dir=templates_dir,
            simulation_iterations=100
        )
        config = _make_config("APP_NAME=test\nDEBUG=false\n", "clean.env")
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) == 0
