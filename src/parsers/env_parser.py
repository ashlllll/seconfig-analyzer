"""
.env File Parser
Parses KEY=VALUE format environment variable files.
"""
import re
from typing import Any, Dict, List, Tuple

from .base_parser import BaseParser
from ..models.config_model import ConfigFile


class EnvParser(BaseParser):
    """
    Parser for .env configuration files.

    Supports:
        - KEY=VALUE pairs
        - Quoted values: KEY="value" or KEY='value'
        - Comments: # this is a comment
        - Empty lines
        - Export prefix: export KEY=VALUE
    """

    # Regex: optional 'export ', then KEY=VALUE
    LINE_PATTERN = re.compile(
        r'^\s*(?:export\s+)?'       # optional 'export'
        r'([A-Za-z_][A-Za-z0-9_]*)' # key
        r'\s*=\s*'                   # equals sign
        r'(.*?)\s*$'                 # value
    )

    COMMENT_PATTERN = re.compile(r'^\s*#')
    EMPTY_PATTERN = re.compile(r'^\s*$')

    def get_file_type(self) -> str:
        return "env"

    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validate .env file format.
        Checks for malformed lines that are not comments or empty.
        """
        errors = []
        lines = self.extract_lines(content)

        for i, line in enumerate(lines, start=1):
            # Skip comments and empty lines
            if self.COMMENT_PATTERN.match(line) or self.EMPTY_PATTERN.match(line):
                continue
            # Must match KEY=VALUE pattern
            if not self.LINE_PATTERN.match(line):
                errors.append(f"Line {i}: Invalid format — '{line.strip()}'")

        is_valid = len(errors) == 0
        return is_valid, errors

    def parse(self, content: str, file_name: str) -> ConfigFile:
        """
        Parse .env file content into a ConfigFile.

        Returns:
            ConfigFile with parsed_content as Dict[str, str]
        """
        is_valid, errors = self.validate(content)
        parsed: Dict[str, Any] = {}
        lines = self.extract_lines(content)

        for line in lines:
            # Skip comments and empty lines
            if self.COMMENT_PATTERN.match(line) or self.EMPTY_PATTERN.match(line):
                continue

            match = self.LINE_PATTERN.match(line)
            if match:
                key = match.group(1).strip()
                value = self._clean_value(match.group(2))
                parsed[key] = value

        return self._build_config_file(
            file_name=file_name,
            content=content,
            parsed_content=parsed,
            is_valid=is_valid,
            parse_errors=errors,
        )

    def _clean_value(self, value: str) -> str:
        """
        Remove surrounding quotes from a value if present.

        Examples:
            "admin123"  → admin123
            'secret'    → secret
            plain_value → plain_value
        """
        value = value.strip()

        if len(value) >= 2:
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

        return value
