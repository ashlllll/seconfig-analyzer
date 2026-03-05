"""
tests/unit/test_utils.py
~~~~~~~~~~~~~~~~~~~~~~~~
Unit tests for src/utils/  (Steps 12 & 13).

Run with:  pytest tests/unit/test_utils.py -v
"""

import json
import os
import re
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ============================================================
# constants
# ============================================================
class TestConstants:

    def test_severity_levels_ordered(self):
        from src.utils.constants import SEVERITY_LEVELS
        assert SEVERITY_LEVELS.index("info") < SEVERITY_LEVELS.index("critical")

    def test_severity_weights_monotonic(self):
        from src.utils.constants import SEVERITY_WEIGHTS
        assert SEVERITY_WEIGHTS["info"] < SEVERITY_WEIGHTS["low"] < SEVERITY_WEIGHTS["critical"]

    def test_nist_functions_present(self):
        from src.utils.constants import NIST_FUNCTIONS
        for fn in ("IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"):
            assert fn in NIST_FUNCTIONS

    def test_cia_impact_weights_range(self):
        from src.utils.constants import CIA_IMPACT_WEIGHTS
        for v in CIA_IMPACT_WEIGHTS.values():
            assert 0.0 <= v <= 1.0

    def test_supported_file_types_includes_basics(self):
        from src.utils.constants import SUPPORTED_FILE_TYPES
        for ext in ("env", "yaml", "json"):
            assert ext in SUPPORTED_FILE_TYPES


# ============================================================
# validator
# ============================================================
class TestFileTypeValidation:

    def test_valid_env(self):
        from src.utils.validator import validate_file_type
        assert validate_file_type("config.env") == "env"

    def test_valid_yaml(self):
        from src.utils.validator import validate_file_type
        assert validate_file_type("app.yaml") == "yaml"

    def test_yml_normalised_to_yaml(self):
        from src.utils.validator import validate_file_type
        assert validate_file_type("config.yml") == "yaml"

    def test_valid_json(self):
        from src.utils.validator import validate_file_type
        assert validate_file_type("settings.json") == "json"

    def test_unsupported_type_raises(self):
        from src.utils.validator import validate_file_type
        with pytest.raises(ValueError, match="Unsupported"):
            validate_file_type("data.csv")

    def test_case_insensitive(self):
        from src.utils.validator import validate_file_type
        assert validate_file_type("config.YAML") == "yaml"


class TestFileSizeValidation:

    def test_within_limit(self):
        from src.utils.validator import validate_file_size
        validate_file_size(5 * 1024 * 1024)  # 5 MB — should not raise

    def test_exactly_at_limit(self):
        from src.utils.validator import validate_file_size
        validate_file_size(10 * 1024 * 1024)  # exactly 10 MB

    def test_exceeds_limit_raises(self):
        from src.utils.validator import validate_file_size
        with pytest.raises(ValueError, match="exceeds"):
            validate_file_size(11 * 1024 * 1024)

    def test_custom_limit(self):
        from src.utils.validator import validate_file_size
        with pytest.raises(ValueError):
            validate_file_size(2_000, max_bytes=1_000)


class TestFieldValidation:

    def test_valid_severity(self):
        from src.utils.validator import validate_severity
        assert validate_severity("CRITICAL") == "critical"

    def test_invalid_severity_raises(self):
        from src.utils.validator import validate_severity
        with pytest.raises(ValueError):
            validate_severity("catastrophic")

    def test_valid_nist_function(self):
        from src.utils.validator import validate_nist_function
        assert validate_nist_function("protect") == "PROTECT"

    def test_invalid_nist_function_raises(self):
        from src.utils.validator import validate_nist_function
        with pytest.raises(ValueError):
            validate_nist_function("ATTACK")

    def test_valid_category(self):
        from src.utils.validator import validate_category
        assert validate_category("Credentials") == "credentials"

    def test_invalid_category_raises(self):
        from src.utils.validator import validate_category
        with pytest.raises(ValueError):
            validate_category("malware")

    def test_valid_probability(self):
        from src.utils.validator import validate_probability
        assert validate_probability(0.5) == 0.5

    def test_probability_out_of_range_raises(self):
        from src.utils.validator import validate_probability
        with pytest.raises(ValueError):
            validate_probability(1.5)

    def test_valid_cia_impact(self):
        from src.utils.validator import validate_cia_impact
        assert validate_cia_impact("HIGH") == "high"


class TestPlaceholderDetection:

    @pytest.mark.parametrize("value,expected", [
        ("${DB_PASSWORD}", True),
        ("<your-secret>", True),
        ("****", True),
        ("change_me", True),
        ("example_value", True),
        ("admin123", False),
        ("P@ssw0rd!", False),
        ("s3cr3tK3y", False),
    ])
    def test_placeholder_detection(self, value, expected):
        from src.utils.validator import is_placeholder_value
        assert is_placeholder_value(value) == expected


class TestContentHash:

    def test_same_content_same_hash(self):
        from src.utils.validator import compute_content_hash
        h1 = compute_content_hash("hello world")
        h2 = compute_content_hash("hello world")
        assert h1 == h2

    def test_different_content_different_hash(self):
        from src.utils.validator import compute_content_hash
        h1 = compute_content_hash("hello world")
        h2 = compute_content_hash("hello world!")
        assert h1 != h2

    def test_hash_is_hex_string(self):
        from src.utils.validator import compute_content_hash
        h = compute_content_hash("test")
        assert re.fullmatch(r"[0-9a-f]{64}", h)


class TestRuleValidation:

    def _valid_rule(self):
        return {
            "id": "CRED-001",
            "name": "Hard-coded Password",
            "category": "credentials",
            "severity": "critical",
            "description": "Password is hard-coded.",
            "detection": {
                "type": "regex",
                "patterns": [r"PASSWORD\s*=\s*['\"]?[a-zA-Z0-9]{6,}"],
            },
            "risk_profile": {
                "likelihood_mean": 0.8,
                "likelihood_std": 0.1,
                "base_severity": 9.0,
            },
        }

    def test_valid_rule_returns_no_errors(self):
        from src.utils.validator import validate_rule_dict
        errors = validate_rule_dict(self._valid_rule())
        assert errors == []

    def test_missing_required_field_returns_error(self):
        from src.utils.validator import validate_rule_dict
        rule = self._valid_rule()
        del rule["severity"]
        errors = validate_rule_dict(rule)
        assert any("severity" in e for e in errors)

    def test_invalid_regex_returns_error(self):
        from src.utils.validator import validate_rule_dict
        rule = self._valid_rule()
        rule["detection"]["patterns"] = ["[unclosed"]
        errors = validate_rule_dict(rule)
        assert any("regex" in e.lower() for e in errors)

    def test_invalid_severity_returns_error(self):
        from src.utils.validator import validate_rule_dict
        rule = self._valid_rule()
        rule["severity"] = "extreme"
        errors = validate_rule_dict(rule)
        assert errors


# ============================================================
# file_handler
# ============================================================
class TestFileHandler:

    def test_read_text_file(self, tmp_path):
        from src.utils.file_handler import read_text_file
        f = tmp_path / "test.txt"
        f.write_text("hello", encoding="utf-8")
        assert read_text_file(f) == "hello"

    def test_read_missing_file_raises(self, tmp_path):
        from src.utils.file_handler import read_text_file
        with pytest.raises(FileNotFoundError):
            read_text_file(tmp_path / "nope.txt")

    def test_write_text_file_creates_parents(self, tmp_path):
        from src.utils.file_handler import write_text_file
        target = tmp_path / "a" / "b" / "c.txt"
        write_text_file(target, "content")
        assert target.read_text() == "content"

    def test_read_write_json(self, tmp_path):
        from src.utils.file_handler import write_json_file, read_json_file
        data = {"key": "value", "num": 42}
        path = tmp_path / "data.json"
        write_json_file(path, data)
        loaded = read_json_file(path)
        assert loaded == data

    def test_list_files_by_extension(self, tmp_path):
        from src.utils.file_handler import list_files
        (tmp_path / "a.yaml").touch()
        (tmp_path / "b.json").touch()
        (tmp_path / "c.env").touch()
        yaml_files = list_files(tmp_path, extensions=["yaml"])
        assert len(yaml_files) == 1
        assert yaml_files[0].name == "a.yaml"

    def test_get_file_info_returns_metadata(self, tmp_path):
        from src.utils.file_handler import get_file_info
        f = tmp_path / "config.env"
        f.write_text("KEY=value\n")
        info = get_file_info(f)
        assert info["name"] == "config.env"
        assert info["line_count"] == 1
        assert info["size_bytes"] > 0

    def test_safe_copy(self, tmp_path):
        from src.utils.file_handler import safe_copy
        src = tmp_path / "src.txt"
        dst = tmp_path / "dst.txt"
        src.write_text("data")
        safe_copy(src, dst)
        assert dst.read_text() == "data"

    def test_safe_copy_no_overwrite_raises(self, tmp_path):
        from src.utils.file_handler import safe_copy
        src = tmp_path / "src.txt"
        dst = tmp_path / "dst.txt"
        src.write_text("data")
        dst.write_text("existing")
        with pytest.raises(FileExistsError):
            safe_copy(src, dst, overwrite=False)


# ============================================================
# config_loader
# ============================================================
class TestConfigLoader:

    def test_get_config_returns_dict(self, tmp_path):
        from src.utils.config_loader import load_config, reset_config
        reset_config()
        # Config file does not exist → uses defaults
        cfg = load_config(str(tmp_path / "nonexistent.yaml"))
        assert isinstance(cfg, dict)
        assert "app" in cfg
        assert "simulation" in cfg

    def test_defaults_are_applied(self, tmp_path):
        from src.utils.config_loader import load_config, reset_config
        reset_config()
        cfg = load_config(str(tmp_path / "nonexistent.yaml"))
        assert cfg["simulation"]["default_iterations"] == 10_000

    def test_override_from_yaml(self, tmp_path):
        from src.utils.config_loader import load_config, reset_config
        reset_config()
        cfg_file = tmp_path / "config.yaml"
        cfg_file.write_text("simulation:\n  default_iterations: 5000\n")
        cfg = load_config(str(cfg_file))
        assert cfg["simulation"]["default_iterations"] == 5000
        # Other defaults still present
        assert cfg["simulation"]["seed"] == 42

    def test_env_var_overrides_log_level(self, tmp_path):
        from src.utils.config_loader import load_config, reset_config
        reset_config()
        with patch.dict(os.environ, {"SECCONFIG_LOG_LEVEL": "DEBUG"}):
            cfg = load_config(str(tmp_path / "nonexistent.yaml"))
        assert cfg["logging"]["level"] == "DEBUG"

    def test_reset_clears_cache(self, tmp_path):
        from src.utils import config_loader
        config_loader.load_config(str(tmp_path / "nonexistent.yaml"))
        config_loader.reset_config()
        assert config_loader._config is None


# ============================================================
# logger
# ============================================================
class TestLogger:

    def test_get_logger_returns_logger(self):
        from src.utils.logger import get_logger
        import logging
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)

    def test_get_logger_same_name_returns_same_instance(self):
        from src.utils.logger import get_logger
        l1 = get_logger("same.name")
        l2 = get_logger("same.name")
        assert l1 is l2

    def test_get_app_logger(self):
        from src.utils.logger import get_app_logger
        import logging
        logger = get_app_logger()
        assert isinstance(logger, logging.Logger)
        assert logger.name == "secconfig"


# ============================================================
# LLM Explainer
# ============================================================
class TestLLMExplainerDisabled:

    def test_disabled_returns_info_message(self):
        from src.core.explainer.llm_explainer import LLMExplainerService
        svc = LLMExplainerService(enabled=False)
        result = svc.explain({}, "Why is CRED-001 critical?")
        assert "disabled" in result.lower()

    def test_build_context_returns_correct_keys(self):
        from src.core.explainer.llm_explainer import LLMExplainerService
        ctx = LLMExplainerService.build_context(
            config_file_name="sample.env",
            issues=[],
            fixes=[],
            initial_risk=72.3,
            final_risk=28.5,
            risk_reduction_pct=60.6,
        )
        assert ctx["config_file"] == "sample.env"
        assert ctx["total_issues"] == 0
        assert ctx["risk_score"] == pytest.approx(72.3)
        assert ctx["risk_reduction"] == pytest.approx(60.6)

    def test_clear_history(self):
        from src.core.explainer.llm_explainer import LLMExplainerService
        svc = LLMExplainerService(enabled=False)
        svc._history.append({"query": "q", "response": "r"})
        svc.clear_history()
        assert svc.conversation_history == []

    def test_no_api_key_returns_warning(self):
        from src.core.explainer.llm_explainer import LLMExplainerService
        with patch.dict(os.environ, {}, clear=True):
            # Remove key if present
            os.environ.pop("OPENAI_API_KEY", None)
            svc = LLMExplainerService(enabled=True, api_key=None)
            result = svc.explain({}, "test query")
        assert "api key" in result.lower() or "key" in result.lower()


class TestPromptBuilder:

    def test_build_returns_system_and_user_keys(self):
        from src.core.explainer.prompt_builder import DynamicPromptBuilder
        builder = DynamicPromptBuilder()
        ctx = {
            "config_file": "app.env",
            "total_issues": 5,
            "critical_count": 2,
            "risk_score": 65.0,
            "risk_reduction": 45.0,
            "issues_summary": [],
        }
        prompt = builder.build(ctx, "Why is this critical?")
        assert "system" in prompt
        assert "user" in prompt
        assert len(prompt["system"]) > 0
        assert len(prompt["user"]) > 0

    def test_persona_changes_with_background(self):
        from src.core.explainer.prompt_builder import DynamicPromptBuilder
        builder = DynamicPromptBuilder()
        ctx = {"total_issues": 1, "critical_count": 0,
               "risk_score": 30.0, "risk_reduction": 10.0, "issues_summary": []}
        prompt_jr = builder.build({**ctx, "user_background": "junior_dev"}, "explain")
        prompt_mgr = builder.build({**ctx, "user_background": "manager"}, "explain")
        # System prompts should differ
        assert prompt_jr["system"] != prompt_mgr["system"]

    def test_diversity_constraint_added(self):
        from src.core.explainer.prompt_builder import DynamicPromptBuilder
        builder = DynamicPromptBuilder()
        ctx = {"total_issues": 0, "critical_count": 0,
               "risk_score": 0.0, "risk_reduction": 0.0, "issues_summary": []}
        prompt = builder.build(ctx, "summarise", avoid_phrases=["Based on the analysis"])
        assert "Based on the analysis" in prompt["system"]

    @pytest.mark.parametrize("query,expected_intent", [
        ("Why is this vulnerable?",       "explain_issue"),
        ("Why is CRED-001 critical?",     "why_critical"),
        ("How do I fix the password issue?", "how_to_fix"),
        ("Explain the risk score",        "risk_explanation"),
        ("Give me a summary",             "summary"),
        ("What is happening here?",       "general_inquiry"),
    ])
    def test_intent_detection(self, query, expected_intent):
        from src.core.explainer.prompt_builder import detect_intent
        assert detect_intent(query) == expected_intent

    def test_overused_phrases_detected(self):
        from src.core.explainer.prompt_builder import DynamicPromptBuilder
        builder = DynamicPromptBuilder(max_history_for_diversity=5)
        history = [
            {"query": "q1", "response": "Based on the analysis, things look bad."},
            {"query": "q2", "response": "Based on the analysis, there are issues."},
            {"query": "q3", "response": "Based on the analysis, here is what I found."},
        ]
        overused = builder.extract_overused_phrases(history)
        assert "Based on the analysis" in overused
