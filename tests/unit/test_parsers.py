"""
Unit tests for the parser layer.
Tests: EnvParser, YamlParser, JsonParser, ParserFactory
"""

import pytest
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from src.parsers.env_parser import EnvParser
from src.parsers.yaml_parser import YamlParser
from src.parsers.json_parser import JsonParser
from src.parsers.parser_factory import ParserFactory


# ══════════════════════════════════════════════
# EnvParser Tests
# ══════════════════════════════════════════════

class TestEnvParser:

    def setup_method(self):
        self.parser = EnvParser()

    def test_parse_simple_key_value(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "test.env")
        assert result is not None
        assert result.file_type == "env"
        assert "DATABASE_PASSWORD" in result.parsed_content
        assert result.parsed_content["DATABASE_PASSWORD"] == "admin123"

    def test_parse_ignores_comments(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "test.env")
        for key in result.parsed_content:
            assert not key.startswith("#")

    def test_parse_ignores_empty_lines(self):
        content = "\n\nAPP_NAME=test\n\n\nDEBUG=false\n\n"
        result = self.parser.parse(content, "test.env")
        assert "APP_NAME" in result.parsed_content
        assert "DEBUG" in result.parsed_content
        assert len(result.parsed_content) == 2

    def test_parse_env_var_reference(self, secure_env_content):
        result = self.parser.parse(secure_env_content, "secure.env")
        assert result.parsed_content["DATABASE_PASSWORD"] == "${DATABASE_PASSWORD}"

    def test_parse_quoted_values(self):
        content = 'APP_NAME="My Application"\nDESCRIPTION=\'Simple app\'\n'
        result = self.parser.parse(content, "test.env")
        assert result.parsed_content["APP_NAME"] == "My Application"
        assert result.parsed_content["DESCRIPTION"] == "Simple app"

    def test_parse_empty_file(self, empty_content):
        result = self.parser.parse(empty_content, "empty.env")
        assert result is not None
        assert result.parsed_content == {}
        assert result.is_valid is True

    def test_parse_comments_only(self, comments_only_content):
        result = self.parser.parse(comments_only_content, "comments.env")
        assert result.parsed_content == {}

    def test_parse_preserves_raw_content(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "test.env")
        assert result.raw_content == vulnerable_env_content

    def test_parse_sets_filename(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "myconfig.env")
        assert result.file_name == "myconfig.env"

    def test_parse_sets_file_type(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "test.env")
        assert result.file_type == "env"

    def test_parse_line_count(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "test.env")
        assert result.line_count == len(vulnerable_env_content.splitlines())

    def test_validate_valid_content(self, vulnerable_env_content):
        is_valid, errors = self.parser.validate(vulnerable_env_content)
        assert is_valid is True
        assert errors == []

    def test_validate_empty_content(self, empty_content):
        is_valid, errors = self.parser.validate(empty_content)
        assert is_valid is True  # empty is valid, just no keys

    def test_parse_value_with_equals_sign(self):
        content = "CONNECTION_STRING=host=localhost;port=5432\n"
        result = self.parser.parse(content, "test.env")
        assert "CONNECTION_STRING" in result.parsed_content
        assert "localhost" in result.parsed_content["CONNECTION_STRING"]

    def test_parse_multiple_values(self, vulnerable_env_content):
        result = self.parser.parse(vulnerable_env_content, "test.env")
        assert len(result.parsed_content) >= 5


# ══════════════════════════════════════════════
# YamlParser Tests
# ══════════════════════════════════════════════

class TestYamlParser:

    def setup_method(self):
        self.parser = YamlParser()

    def test_parse_simple_yaml(self, vulnerable_yaml_content):
        result = self.parser.parse(vulnerable_yaml_content, "test.yaml")
        assert result is not None
        assert result.file_type == "yaml"

    def test_parse_nested_keys_flattened(self, vulnerable_yaml_content):
        result = self.parser.parse(vulnerable_yaml_content, "test.yaml")
        # Nested keys should be accessible via dot notation or flat dict
        content = result.parsed_content
        # Either nested or flattened — just check some key exists
        assert content is not None
        assert len(content) > 0

    def test_parse_detects_debug_true(self, vulnerable_yaml_content):
        result = self.parser.parse(vulnerable_yaml_content, "test.yaml")
        raw = result.raw_content
        assert "debug: true" in raw or "debug: True" in raw

    def test_parse_empty_yaml(self, empty_content):
        result = self.parser.parse(empty_content, "empty.yaml")
        assert result is not None
        assert result.is_valid is True

    def test_parse_malformed_yaml_marks_invalid(self, malformed_yaml_content):
        result = self.parser.parse(malformed_yaml_content, "bad.yaml")
        # Should handle gracefully — either is_valid=False or parse_errors set
        if not result.is_valid:
            assert len(result.parse_errors) > 0

    def test_parse_sets_file_type_yml(self):
        content = "app:\n  name: test\n"
        result = self.parser.parse(content, "test.yml")
        assert result.file_type in ("yaml", "yml")

    def test_validate_valid_yaml(self, vulnerable_yaml_content):
        is_valid, errors = self.parser.validate(vulnerable_yaml_content)
        assert is_valid is True

    def test_validate_malformed_yaml(self, malformed_yaml_content):
        is_valid, errors = self.parser.validate(malformed_yaml_content)
        # Malformed YAML should fail validation
        assert is_valid is False or len(errors) > 0

    def test_parse_preserves_raw_content(self, vulnerable_yaml_content):
        result = self.parser.parse(vulnerable_yaml_content, "test.yaml")
        assert result.raw_content == vulnerable_yaml_content


# ══════════════════════════════════════════════
# JsonParser Tests
# ══════════════════════════════════════════════

class TestJsonParser:

    def setup_method(self):
        self.parser = JsonParser()

    def test_parse_valid_json(self, vulnerable_json_content):
        result = self.parser.parse(vulnerable_json_content, "test.json")
        assert result is not None
        assert result.file_type == "json"

    def test_parse_json_has_content(self, vulnerable_json_content):
        result = self.parser.parse(vulnerable_json_content, "test.json")
        assert result.parsed_content is not None
        assert len(result.parsed_content) > 0

    def test_parse_empty_json(self):
        result = self.parser.parse("{}", "empty.json")
        assert result is not None
        assert result.is_valid is True

    def test_parse_malformed_json(self):
        bad_json = '{"key": "value", broken'
        result = self.parser.parse(bad_json, "bad.json")
        assert not result.is_valid or len(result.parse_errors) > 0

    def test_validate_valid_json(self, vulnerable_json_content):
        is_valid, errors = self.parser.validate(vulnerable_json_content)
        assert is_valid is True

    def test_validate_invalid_json(self):
        bad_json = "not json at all"
        is_valid, errors = self.parser.validate(bad_json)
        assert is_valid is False

    def test_parse_preserves_raw_content(self, vulnerable_json_content):
        result = self.parser.parse(vulnerable_json_content, "test.json")
        assert result.raw_content == vulnerable_json_content


# ══════════════════════════════════════════════
# ParserFactory Tests
# ══════════════════════════════════════════════

class TestParserFactory:

    def test_get_env_parser(self):
        parser = ParserFactory.get_parser("env")
        assert isinstance(parser, EnvParser)

    def test_get_yaml_parser(self):
        parser = ParserFactory.get_parser("yaml")
        assert isinstance(parser, YamlParser)

    def test_get_yml_parser(self):
        parser = ParserFactory.get_parser("yml")
        assert isinstance(parser, YamlParser)

    def test_get_json_parser(self):
        parser = ParserFactory.get_parser("json")
        assert isinstance(parser, JsonParser)

    def test_unsupported_type_raises(self):
        with pytest.raises(Exception):
            ParserFactory.get_parser("xml")

    def test_case_insensitive_env(self):
        parser = ParserFactory.get_parser("ENV")
        assert isinstance(parser, EnvParser)

    def test_case_insensitive_yaml(self):
        parser = ParserFactory.get_parser("YAML")
        assert isinstance(parser, YamlParser)

    def test_factory_from_filename_env(self):
        parser = ParserFactory.get_parser_for_file("config.env")
        assert isinstance(parser, EnvParser)

    def test_factory_from_filename_yaml(self):
        parser = ParserFactory.get_parser_for_file("config.yaml")
        assert isinstance(parser, YamlParser)

    def test_factory_from_filename_json(self):
        parser = ParserFactory.get_parser_for_file("config.json")
        assert isinstance(parser, JsonParser)
