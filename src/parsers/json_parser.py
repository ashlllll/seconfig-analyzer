"""
JSON File Parser
Parses .json configuration files.
"""
import json
from typing import Any, Dict, List, Tuple

from .base_parser import BaseParser
from ..models.config_model import ConfigFile


class JsonParser(BaseParser):
    """
    Parser for JSON configuration files.

    Supports:
        - Nested objects and arrays
        - Flattened key paths for rule matching
    """

    def get_file_type(self) -> str:
        return "json"

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validate JSON syntax.
        """
        errors = []
        try:
            json.loads(content)
        except json.JSONDecodeError as e:
            errors.append(f"JSON syntax error at line {e.lineno}: {e.msg}")

        is_valid = len(errors) == 0
        return is_valid, errors

    def parse(self, content: str, file_name: str) -> ConfigFile:
        """
        Parse JSON file content into a ConfigFile.

        Returns:
            ConfigFile with parsed_content as nested Dict
            AND a flat version for rule matching
        """
        is_valid, errors = self.validate(content)
        parsed: Dict[str, Any] = {}

        if is_valid:
            try:
                raw_parsed = json.loads(content)
                if isinstance(raw_parsed, dict):
                    parsed = raw_parsed
                    parsed["_flat"] = self._flatten(raw_parsed)
                else:
                    errors.append("JSON root must be an object (dictionary)")
                    is_valid = False
            except json.JSONDecodeError as e:
                errors.append(f"Parse error: {str(e)}")
                is_valid = False

        return self._build_config_file(
            file_name=file_name,
            content=content,
            parsed_content=parsed,
            is_valid=is_valid,
            parse_errors=errors,
        )

    def _flatten(self, data: Any, parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        """
        Flatten a nested JSON object using dot notation.

        Example:
            {"database": {"password": "123"}}
            → {"database.password": "123"}
        """
        items: Dict[str, Any] = {}

        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{parent_key}{sep}{key}" if parent_key else str(key)
                if isinstance(value, (dict, list)):
                    items.update(self._flatten(value, new_key, sep=sep))
                else:
                    items[new_key] = value

        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{parent_key}[{i}]"
                if isinstance(item, (dict, list)):
                    items.update(self._flatten(item, new_key, sep=sep))
                else:
                    items[new_key] = item

        return items
