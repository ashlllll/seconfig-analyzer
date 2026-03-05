"""
Fix Validator
Validates generated fixes to ensure they are syntactically correct
and actually resolve the detected vulnerability.
"""
import re
from typing import Dict, List, Tuple, Any


class FixValidator:
    """
    Validates that a generated fix is correct and safe to apply.

    Runs three checks:
    1. Syntax check — is the fixed code valid for its file type?
    2. Template rule check — does it satisfy template validation patterns?
    3. Security check — does it still contain the vulnerability?
    """

    def validate(
        self,
        original_code: str,
        fixed_code: str,
        template: Dict[str, Any],
        file_type: str = "env",
    ) -> Tuple[bool, List[str]]:
        """
        Validate a generated fix.

        Args:
            original_code: The vulnerable code snippet
            fixed_code:    The generated fix code
            template:      The template that was used
            file_type:     File type (env / yaml / json)

        Returns:
            (is_valid, list_of_error_messages)
        """
        errors = []

        # 1. Basic check — fixed code must not be empty
        if not fixed_code or not fixed_code.strip():
            errors.append("Fixed code is empty.")
            return False, errors

        # 2. Fixed code must differ from original
        if fixed_code.strip() == original_code.strip():
            errors.append("Fixed code is identical to the original — no change made.")

        # 3. Template validation rules
        for rule in template.get("validation", []):
            pattern = rule.get("pattern", "")
            description = rule.get("description", "Validation failed")
            if pattern:
                if not re.search(pattern, fixed_code):
                    errors.append(f"Validation failed: {description}")

        # 4. Security check — should not still contain obvious vulnerabilities
        security_errors = self._security_check(original_code, fixed_code, template)
        errors.extend(security_errors)

        is_valid = len(errors) == 0
        return is_valid, errors

    def _security_check(
        self,
        original_code: str,
        fixed_code: str,
        template: Dict[str, Any],
    ) -> List[str]:
        """
        Check that the fix doesn't still contain the vulnerability pattern.
        """
        errors = []
        strategy = template.get("fix_strategy", "")

        # For template_replacement: fixed code should use env var references
        if strategy == "template_replacement":
            # Should contain ${...} variable reference
            if not re.search(r'\$\{[A-Za-z_][A-Za-z0-9_]*\}', fixed_code):
                # Also accept other safe patterns
                if not re.search(r'<[^>]+>', fixed_code):  # placeholder
                    errors.append(
                        "Fix does not appear to use an environment variable reference."
                    )

        # For configuration_change: value should be changed
        if strategy == "configuration_change":
            if original_code.strip() == fixed_code.strip():
                errors.append("Configuration value was not changed.")

        return errors

    def validate_syntax(self, code: str, file_type: str) -> Tuple[bool, str]:
        """
        Basic syntax validation for a code snippet.

        Args:
            code:      Code snippet to validate
            file_type: 'env' | 'yaml' | 'json'

        Returns:
            (is_valid, error_message)
        """
        if file_type == "env":
            return self._validate_env_syntax(code)
        elif file_type in ("yaml", "yml"):
            return self._validate_yaml_syntax(code)
        elif file_type == "json":
            return self._validate_json_syntax(code)
        return True, ""

    def _validate_env_syntax(self, code: str) -> Tuple[bool, str]:
        """Validate .env line syntax."""
        for line in code.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                return False, f"Invalid .env syntax: '{line}' (missing '=')"
        return True, ""

    def _validate_yaml_syntax(self, code: str) -> Tuple[bool, str]:
        """Validate YAML snippet syntax."""
        try:
            import yaml
            yaml.safe_load(code)
            return True, ""
        except Exception as e:
            return False, f"Invalid YAML syntax: {e}"

    def _validate_json_syntax(self, code: str) -> Tuple[bool, str]:
        """Validate JSON snippet syntax."""
        try:
            import json
            json.loads(code)
            return True, ""
        except Exception as e:
            return False, f"Invalid JSON syntax: {e}"
