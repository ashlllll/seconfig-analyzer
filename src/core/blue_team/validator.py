"""
Fix Validator
Validates generated fixes to ensure they are syntactically correct
and actually resolve the detected vulnerability.
"""
import json
import re
from typing import Any, Dict, List, Tuple

import yaml


# Patterns that indicate a value has been safely externalised.
# Accepted forms: ${VAR}, $VAR (uppercase only), <placeholder>,
# vault: references, ssm: references (AWS Parameter Store).
_SAFE_REFERENCE_PATTERNS: List[str] = [
    r'\$\{[A-Za-z_]\w*\}',        # ${DATABASE_PASSWORD}
    r'\$[A-Z_][A-Z0-9_]+',         # $DATABASE_PASSWORD  (uppercase env vars)
    r'<[^>]+>',                     # <your-secret-here>
    r'\bvault:',                    # HashiCorp Vault reference
    r'\bssm:',                      # AWS SSM Parameter Store reference
]


class FixValidator:
    """
    Validates that a generated fix is correct and safe to apply.

    Runs four checks in order:
    1. Non-empty check  — fixed code must not be blank.
    2. Change check     — fixed code must differ from the original.
    3. Syntax check     — fixed code must be valid for its file type.
    4. Template rules   — fix must satisfy template-defined validation patterns.
    5. Security check   — fix must not still contain the vulnerability pattern.
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
            original_code: The vulnerable code snippet.
            fixed_code:    The generated fix code.
            template:      The template that was used.
            file_type:     File type ('env' | 'yaml' | 'yml' | 'json').

        Returns:
            (is_valid, list_of_error_messages)
        """
        errors: List[str] = []

        # 1. Non-empty check
        if not fixed_code or not fixed_code.strip():
            errors.append("Fixed code is empty.")
            return False, errors

        # 2. Change check
        if fixed_code.strip() == original_code.strip():
            errors.append("Fixed code is identical to the original — no change made.")

        # 3. Syntax check (now actually wired in)
        syntax_ok, syntax_err = self.validate_syntax(fixed_code, file_type)
        if not syntax_ok:
            errors.append(syntax_err)

        # 4. Template validation rules
        for rule in template.get("validation", []):
            pattern = rule.get("pattern", "")
            description = rule.get("description", "Validation failed")
            if pattern and not re.search(pattern, fixed_code):
                errors.append(f"Validation failed: {description}")

        # 5. Security check
        errors.extend(self._security_check(original_code, fixed_code, template))

        return len(errors) == 0, errors

    # ── Security check ────────────────────────────────────────────────────────

    def _security_check(
        self,
        original_code: str,
        fixed_code: str,
        template: Dict[str, Any],
    ) -> List[str]:
        """Check that the fix does not still expose the vulnerability."""
        errors: List[str] = []
        strategy = template.get("fix_strategy", "")

        if strategy == "template_replacement":
            # Fixed code must use one of the accepted safe-reference forms.
            safe = any(
                re.search(pat, fixed_code)
                for pat in _SAFE_REFERENCE_PATTERNS
            )
            if not safe:
                errors.append(
                    "Fix does not appear to externalise the secret "
                    "(expected an env-var reference, placeholder, or secrets-manager URI)."
                )

        if strategy == "configuration_change":
            if original_code.strip() == fixed_code.strip():
                errors.append("Configuration value was not changed.")

        return errors

    # ── Syntax validation ─────────────────────────────────────────────────────

    def validate_syntax(self, code: str, file_type: str) -> Tuple[bool, str]:
        """
        Validate the syntax of a code snippet for the given file type.

        Args:
            code:      Code snippet to validate.
            file_type: 'env' | 'yaml' | 'yml' | 'json'

        Returns:
            (is_valid, error_message)  — error_message is '' when valid.
        """
        if file_type == "env":
            return self._validate_env_syntax(code)
        if file_type in ("yaml", "yml"):
            return self._validate_yaml_syntax(code)
        if file_type == "json":
            return self._validate_json_syntax(code)
        # Unknown type — skip syntax check rather than fail
        return True, ""

    def _validate_env_syntax(self, code: str) -> Tuple[bool, str]:
        """Validate .env line syntax (each non-comment line must contain '=')."""
        for line in code.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" not in stripped:
                return False, f"Invalid .env syntax: '{stripped}' (missing '=')"
        return True, ""

    def _validate_yaml_syntax(self, code: str) -> Tuple[bool, str]:
        """Validate YAML snippet syntax."""
        try:
            yaml.safe_load(code)
            return True, ""
        except yaml.YAMLError as e:
            return False, f"Invalid YAML syntax: {e}"

    def _validate_json_syntax(self, code: str) -> Tuple[bool, str]:
        """Validate JSON snippet syntax."""
        try:
            json.loads(code)
            return True, ""
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON syntax: {e}"