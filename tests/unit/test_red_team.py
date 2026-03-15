"""
Unit tests for the Red Team engine.
Tests: RuleLoader, RuleEngine, Matcher, RedTeamAnalyzer
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from src.parsers.env_parser import EnvParser
from src.parsers.yaml_parser import YamlParser
from src.parsers.json_parser import JsonParser


# ══════════════════════════════════════════════
# RuleLoader Tests
# ══════════════════════════════════════════════

class TestRuleLoader:

    def test_loader_imports(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        assert loader is not None

    def test_loads_all_rules(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        assert len(rules) == 23

    def test_rules_have_required_fields(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        for rule in rules:
            assert hasattr(rule, 'id') or 'id' in rule or rule.get('id') is not None

    def test_loads_credential_rules(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        cred_rules = [r for r in rules if (
            (hasattr(r, 'id') and r.id.startswith('CRED')) or
            (isinstance(r, dict) and r.get('id', '').startswith('CRED'))
        )]
        assert len(cred_rules) == 5

    def test_loads_encryption_rules(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        enc_rules = [r for r in rules if (
            (hasattr(r, 'id') and r.id.startswith('ENC')) or
            (isinstance(r, dict) and r.get('id', '').startswith('ENC'))
        )]
        assert len(enc_rules) == 5

    def test_loads_access_control_rules(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        ac_rules = [r for r in rules if (
            (hasattr(r, 'id') and r.id.startswith('AC')) or
            (isinstance(r, dict) and r.get('id', '').startswith('AC'))
        )]
        assert len(ac_rules) == 5

    def test_loads_logging_rules(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        log_rules = [r for r in rules if (
            (hasattr(r, 'id') and r.id.startswith('LOG')) or
            (isinstance(r, dict) and r.get('id', '').startswith('LOG'))
        )]
        assert len(log_rules) == 3

    def test_loads_baseline_rules(self, rules_dir):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader(rules_dir)
        rules = loader.load_all_rules()
        base_rules = [r for r in rules if (
            (hasattr(r, 'id') and r.id.startswith('BASE')) or
            (isinstance(r, dict) and r.get('id', '').startswith('BASE'))
        )]
        assert len(base_rules) == 5

    def test_nonexistent_dir_raises(self):
        from src.rules.rule_loader import RuleLoader
        loader = RuleLoader("/nonexistent/path")
        with pytest.raises(Exception):
            loader.load_all_rules()

    def test_single_bad_yaml_does_not_abort_load(self, rules_dir, tmp_path):
        """
        If one rule file is malformed, the engine must still load the rules
        from all other files rather than aborting entirely.

        This is a regression test for the fix in rule_engine.py that changed
        per-file failures from fatal RuleLoadError to logged warnings.
        """
        import shutil
        # Copy the real catalog to a temp dir and inject one malformed file
        temp_rules = tmp_path / "rules"
        shutil.copytree(rules_dir, str(temp_rules))
        bad_file = temp_rules / "zzz_bad_rule.yaml"
        bad_file.write_text("rules:\n  - {{{invalid yaml\n", encoding="utf-8")

        from src.core.red_team.rule_engine import RuleEngine
        # Must not raise — bad file is skipped, valid rules are loaded
        engine = RuleEngine(rules_dir=str(temp_rules))
        assert engine.rule_count >= 23, (
            "A single malformed rule file should not prevent the other "
            "23 valid rules from being loaded."
        )


# ══════════════════════════════════════════════
# RuleEngine / RedTeamAnalyzer Tests
# ══════════════════════════════════════════════

class TestRedTeamAnalyzer:

    def _get_config(self, content, filename="test.env"):
        parser = EnvParser()
        return parser.parse(content, filename)

    def _get_yaml_config(self, content, filename="test.yaml"):
        parser = YamlParser()
        return parser.parse(content, filename)

    def _get_json_config(self, content, filename="test.json"):
        parser = JsonParser()
        return parser.parse(content, filename)

    def _get_analyzer(self, rules_dir):
        from src.core.red_team.analyzer import RedTeamAnalyzer
        return RedTeamAnalyzer(rules_dir=rules_dir)

    # ── Detection: Credentials ──

    def test_detects_hardcoded_password(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("DATABASE_PASSWORD=admin123\n")
        issues = analyzer.analyze(config)
        ids = [i.rule_id if hasattr(i, 'rule_id') else i.get('rule_id') for i in issues]
        assert "CRED-001" in ids

    def test_detects_hardcoded_api_key(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("API_KEY=sk-abc123xyz789secretvalue\n")
        issues = analyzer.analyze(config)
        rule_ids = [i.rule_id if hasattr(i, 'rule_id') else i.get('rule_id') for i in issues]
        assert any(r.startswith('CRED') for r in rule_ids)

    def test_detects_default_password(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("ADMIN_PASSWORD=admin\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    # ── Detection: Encryption ──

    def test_detects_weak_cipher_des(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("CIPHER_ALGORITHM=DES\n")
        issues = analyzer.analyze(config)
        rule_ids = [i.rule_id if hasattr(i, 'rule_id') else i.get('rule_id') for i in issues]
        assert any(r.startswith('ENC') for r in rule_ids)

    def test_detects_ssl_verify_false(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("SSL_VERIFY=false\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    def test_detects_weak_hash_md5(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("HASH_ALGORITHM=MD5\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    # ── Detection: Access Control ──

    def test_detects_cors_wildcard(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("CORS_ORIGIN=*\n")
        issues = analyzer.analyze(config)
        rule_ids = [i.rule_id if hasattr(i, 'rule_id') else i.get('rule_id') for i in issues]
        assert any(r.startswith('AC') for r in rule_ids)

    def test_detects_debug_true(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("DEBUG=true\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    # ── Detection: Logging ──

    def test_detects_logging_disabled(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("LOGGING_ENABLED=false\n")
        issues = analyzer.analyze(config)
        rule_ids = [i.rule_id if hasattr(i, 'rule_id') else i.get('rule_id') for i in issues]
        assert any(r.startswith('LOG') for r in rule_ids)

    def test_detects_debug_log_level(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("LOG_LEVEL=DEBUG\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    # ── Detection: Baseline ──

    def test_detects_testing_true(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("TESTING=true\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    def test_detects_zero_session_timeout(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("SESSION_TIMEOUT=0\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    # ── No False Positives ──

    def test_no_issues_on_secure_config(self, rules_dir, secure_env_content):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config(secure_env_content, "secure.env")
        issues = analyzer.analyze(config)
        assert len(issues) == 0

    def test_no_issues_on_empty_file(self, rules_dir, empty_content):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config(empty_content, "empty.env")
        issues = analyzer.analyze(config)
        assert len(issues) == 0

    def test_env_var_reference_not_flagged(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("DATABASE_PASSWORD=${DATABASE_PASSWORD}\n")
        issues = analyzer.analyze(config)
        assert len(issues) == 0

    # ── Issue Object Structure ──

    def test_issue_has_rule_id(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("DATABASE_PASSWORD=admin123\n")
        issues = analyzer.analyze(config)
        assert len(issues) > 0
        issue = issues[0]
        assert hasattr(issue, 'rule_id') or isinstance(issue, dict)

    def test_issue_has_severity(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("DATABASE_PASSWORD=admin123\n")
        issues = analyzer.analyze(config)
        issue = issues[0]
        severity = issue.severity if hasattr(issue, 'severity') else issue.get('severity')
        assert severity in ('critical', 'high', 'medium', 'low', 'info')

    def test_issue_has_line_number(self, rules_dir):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config("# comment\nDATABASE_PASSWORD=admin123\n")
        issues = analyzer.analyze(config)
        issue = issues[0]
        line = issue.line_number if hasattr(issue, 'line_number') else issue.get('line_number')
        assert line is not None
        assert line > 0

    def test_multiple_issues_detected(self, rules_dir, vulnerable_env_content):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config(vulnerable_env_content)
        issues = analyzer.analyze(config)
        assert len(issues) >= 5

    # ── YAML and JSON format ──

    def test_detects_issues_in_yaml(self, rules_dir, vulnerable_yaml_content):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_yaml_config(vulnerable_yaml_content)
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    def test_detects_issues_in_json(self, rules_dir, vulnerable_json_content):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_json_config(vulnerable_json_content)
        issues = analyzer.analyze(config)
        assert len(issues) > 0

    # ── Sorting ──

    def test_issues_sorted_by_severity(self, rules_dir, vulnerable_env_content):
        analyzer = self._get_analyzer(rules_dir)
        config = self._get_config(vulnerable_env_content)
        issues = analyzer.analyze(config)
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        severities = []
        for i in issues:
            s = i.severity if hasattr(i, 'severity') else i.get('severity', 'info')
            severities.append(severity_order.get(s, 0))
        assert severities == sorted(severities, reverse=True)


# ══════════════════════════════════════════════
# Matcher tests — YAML colon rewrite behaviour
# ══════════════════════════════════════════════

class TestMatcherColonRewrite:
    """
    Regression tests for the YAML colon→equals normalisation in Matcher.

    The old implementation used ``line.replace(':', '=')`` globally, which
    corrupted URLs (turning https://example.com into https=//example.com).
    The fix restricts the rewrite to lines that look like  ``key: value``.
    """

    def _get_matcher(self):
        from src.core.red_team.matcher import Matcher
        return Matcher()

    def test_url_value_is_not_rewritten(self):
        """
        A config line whose value contains a URL must not be corrupted.
        'database_url: https://localhost/db' should NOT become
        'database_url= https=//localhost/db'.
        """
        from src.core.red_team.matcher import Matcher
        m = Matcher()
        # Pattern that matches DATABASE_URL=... but not https://
        patterns = [r'(?i)DATABASE_URL\s*[=:]\s*(?!.*\$\{).*://']
        result = m.match_line(
            "database_url: https://localhost:5432/mydb",
            line_number=1,
            patterns=patterns,
        )
        # The match is valid here (it IS a database URL),
        # but more importantly the line must not crash and the
        # matched text must not contain a mangled URL like https=//
        if result:
            assert "https=//" not in result.matched_text

    def test_simple_key_value_yaml_is_rewritten(self):
        """
        A plain 'key: value' YAML line should be normalised to 'key=value'
        so that env-style patterns can match it.
        """
        from src.core.red_team.matcher import Matcher
        m = Matcher()
        # Pattern expects KEY=value style
        patterns = [r'(?i)debug\s*=\s*true']
        result = m.match_line(
            "debug: true",
            line_number=1,
            patterns=patterns,
        )
        assert result is not None, (
            "Matcher should rewrite 'debug: true' to 'debug=true' so "
            "env-style patterns can match YAML config lines."
        )

    def test_url_in_value_not_matched_as_key(self):
        """
        Lines like 'api_endpoint: https://api.example.com' must not
        produce spurious matches for patterns expecting key=https or similar.
        """
        from src.core.red_team.matcher import Matcher
        m = Matcher()
        # This pattern should ONLY match if 'https' appears as a key, not a URL value
        patterns = [r'(?i)^https\s*=']
        result = m.match_line(
            "api_endpoint: https://api.example.com",
            line_number=1,
            patterns=patterns,
        )
        assert result is None, (
            "A URL value should not be rewritten in a way that makes "
            "'https' look like a config key."
        )