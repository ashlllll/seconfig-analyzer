"""
Integration tests — full end-to-end workflow using synthetic config files.
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


def get_service(rules_dir, templates_dir, iterations=200):
    from services.analysis_service import AnalysisService
    return AnalysisService(
        rules_dir=rules_dir,
        templates_dir=templates_dir,
        simulation_iterations=iterations
    )


def parse_file(filepath):
    from parsers.parser_factory import ParserFactory
    ext = filepath.rsplit('.', 1)[-1].lower()
    parser = ParserFactory.get_parser(ext)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    return parser.parse(content, os.path.basename(filepath))


# ── Vulnerable configs produce issues ──

class TestVulnerableConfigs:

    def test_sample_01_env_has_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_01.env'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) >= 5

    def test_sample_02_env_has_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_02.env'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) >= 3

    def test_sample_03_yaml_has_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_03.yaml'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) >= 3

    def test_sample_04_json_has_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_04.json'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) >= 3

    def test_vulnerable_config_risk_score_above_zero(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_01.env'))
        report = svc.run_full_analysis(config)
        score = (report.initial_risk_score
                 if hasattr(report, 'initial_risk_score')
                 else report.get('initial_risk_score', 0))
        assert score > 0

    def test_vulnerable_config_generates_fixes(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_01.env'))
        report = svc.run_full_analysis(config)
        fixes = report.fixes if hasattr(report, 'fixes') else report.get('fixes', [])
        assert len(fixes) > 0


# ── Secure configs produce zero issues ──

class TestSecureConfigs:

    def test_best_practice_01_no_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'secure', 'best_practice_01.env'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) == 0

    def test_best_practice_02_no_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'secure', 'best_practice_02.yaml'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) == 0

    def test_best_practice_03_no_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'secure', 'best_practice_03.json'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) == 0


# ── Edge cases handled gracefully ──

class TestEdgeCases:

    def test_empty_file_no_crash(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'edge_cases', 'empty.env'))
        report = svc.run_full_analysis(config)
        assert report is not None

    def test_comments_only_no_issues(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'edge_cases', 'comments_only.env'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) == 0

    def test_single_issue_detected(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'edge_cases', 'single_issue.env'))
        report = svc.run_full_analysis(config)
        issues = report.issues if hasattr(report, 'issues') else report.get('issues', [])
        assert len(issues) == 1

    def test_large_file_no_crash(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'edge_cases', 'large_file.env'))
        report = svc.run_full_analysis(config)
        assert report is not None

    def test_no_issues_file_zero_risk(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'edge_cases', 'no_issues.env'))
        report = svc.run_full_analysis(config)
        score = (report.initial_risk_score
                 if hasattr(report, 'initial_risk_score')
                 else report.get('initial_risk_score', -1))
        assert score == 0.0


# ── Risk reduction after remediation ──

class TestRiskReduction:

    def test_risk_reduced_after_fixes(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_01.env'))
        report = svc.run_full_analysis(config)
        initial = (report.initial_risk_score
                   if hasattr(report, 'initial_risk_score')
                   else report.get('initial_risk_score', 0))
        final = (report.final_risk_score
                 if hasattr(report, 'final_risk_score')
                 else report.get('final_risk_score', 0))
        assert final <= initial

    def test_risk_reduction_percentage_positive(self, rules_dir, templates_dir, synthetic_data_dir):
        svc = get_service(rules_dir, templates_dir)
        config = parse_file(os.path.join(synthetic_data_dir, 'vulnerable', 'sample_01.env'))
        report = svc.run_full_analysis(config)
        pct = (report.risk_reduction_percentage
               if hasattr(report, 'risk_reduction_percentage')
               else report.get('risk_reduction_percentage', -1))
        assert pct >= 0
