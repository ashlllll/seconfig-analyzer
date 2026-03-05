"""
YAML File Parser
Parses .yaml / .yml configuration files.
"""
from typing import Any, Dict, List, Tuple

import yaml

from .base_parser import BaseParser
from ..models.config_model import ConfigFile


class YamlParser(BaseParser):
    """
    Parser for YAML configuration files (.yaml / .yml).

    Supports:
        - Nested structures (flattened with dot notation for rule matching)
        - Lists and dictionaries
        - YAML anchors and aliases
    """

    def get_file_type(self) -> str:
        return "yaml"

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validate YAML syntax.
        """
        errors = []
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            errors.append(f"YAML syntax error: {str(e)}")

        is_valid = len(errors) == 0
        return is_valid, errors

    def parse(self, content: str, file_name: str) -> ConfigFile:
        """
        Parse YAML file content into a ConfigFile.

        Returns:
            ConfigFile with parsed_content as nested Dict
            AND a flat version for rule matching
        """
        is_valid, errors = self.validate(content)
        parsed: Dict[str, Any] = {}

        if is_valid:
            try:
                raw_parsed = yaml.safe_load(content)
                if raw_parsed is None:
                    raw_parsed = {}
                if isinstance(raw_parsed, dict):
                    parsed = raw_parsed
                    # Add flattened version for easier rule matching
                    parsed["_flat"] = self._flatten(raw_parsed)
                else:
                    errors.append("YAML root must be a mapping (dictionary)")
                    is_valid = False
            except yaml.YAMLError as e:
                errors.append(f"Parse error: {str(e)}")
                is_valid = False

        return self._build_config_file(
            file_name=file_name,
            content=content,
            parsed_content=parsed,
            is_valid=is_valid,
            parse_errors=errors,
        )

    def _flatten(self, data: Dict, parent_key: str = "", sep: str = ".") -> Dict[str, Any]:
        """
        Flatten a nested dictionary using dot notation.

        Example:
            {"database": {"password": "123"}}
            → {"database.password": "123"}
        """
        items: Dict[str, Any] = {}

        for key, value in data.items():
            new_key = f"{parent_key}{sep}{key}" if parent_key else str(key)

            if isinstance(value, dict):
                items.update(self._flatten(value, new_key, sep=sep))
            elif isinstance(value, list):
                items[new_key] = value
                # Also index list items
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        items.update(self._flatten(item, f"{new_key}[{i}]", sep=sep))
                    else:
                        items[f"{new_key}[{i}]"] = item
            else:
                items[new_key] = value

        return items
