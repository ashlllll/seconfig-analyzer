"""
validator.py
~~~~~~~~~~~~
Data validation helpers for SecConfig Analyzer.

These functions are *pure* (no side-effects) and raise ``ValueError`` on
invalid input so callers can handle errors at the appropriate layer.
"""

import hashlib
import re
from pathlib import Path
from typing import Any

from src.utils.constants import (
    SUPPORTED_FILE_TYPES,
    MAX_FILE_SIZE_BYTES,
    SEVERITY_LEVELS,
    NIST_FUNCTIONS,
    ISSUE_CATEGORIES,
    CIA_IMPACT_WEIGHTS,
)

# ---------------------------------------------------------------------------
# File validation
# ---------------------------------------------------------------------------

def validate_file_type(file_name: str) -> str:
    """
    Return the normalised file type (``env`` | ``yaml`` | ``json``) or raise.

    Parameters
    ----------
    file_name:
        Original file name, e.g. ``"config.yaml"``.

    Returns
    -------
    str
        One of ``SUPPORTED_FILE_TYPES`` (``yml`` is normalised to ``yaml``).

    Raises
    ------
    ValueError
        When the extension is not supported.
    """
    ext = Path(file_name).suffix.lstrip(".").lower()
    if ext == "yml":
        ext = "yaml"
    if ext not in SUPPORTED_FILE_TYPES:
        raise ValueError(
            f"Unsupported file type '{ext}'. "
            f"Accepted types: {', '.join(SUPPORTED_FILE_TYPES)}"
        )
    return ext


def validate_file_size(size_bytes: int, max_bytes: int = MAX_FILE_SIZE_BYTES) -> None:
    """
    Raise ``ValueError`` when *size_bytes* exceeds the allowed maximum.
    """
    if size_bytes > max_bytes:
        max_mb = max_bytes / (1024 * 1024)
        actual_mb = size_bytes / (1024 * 1024)
        raise ValueError(
            f"File size {actual_mb:.1f} MB exceeds the {max_mb:.0f} MB limit."
        )


def validate_file_content(content: str) -> None:
    """
    Raise ``ValueError`` when *content* is empty or contains only whitespace.
    """
    if not content or not content.strip():
        raise ValueError("File content is empty or contains only whitespace.")


# ---------------------------------------------------------------------------
# Model / field validation
# ---------------------------------------------------------------------------

def validate_severity(severity: str) -> str:
    """Return *severity* if valid, else raise ``ValueError``."""
    severity = severity.lower()
    if severity not in SEVERITY_LEVELS:
        raise ValueError(
            f"Invalid severity '{severity}'. Must be one of: {SEVERITY_LEVELS}"
        )
    return severity


def validate_nist_function(function: str) -> str:
    """Return *function* (upper-cased) if valid, else raise ``ValueError``."""
    function = function.upper()
    if function not in NIST_FUNCTIONS:
        raise ValueError(
            f"Invalid NIST function '{function}'. Must be one of: {NIST_FUNCTIONS}"
        )
    return function


def validate_category(category: str) -> str:
    """Return *category* if valid, else raise ``ValueError``."""
    category = category.lower()
    if category not in ISSUE_CATEGORIES:
        raise ValueError(
            f"Invalid category '{category}'. Must be one of: {ISSUE_CATEGORIES}"
        )
    return category


def validate_cia_impact(label: str) -> str:
    """Return the normalised CIA label or raise ``ValueError``."""
    label = label.lower()
    if label not in CIA_IMPACT_WEIGHTS:
        raise ValueError(
            f"Invalid CIA impact label '{label}'. "
            f"Must be one of: {list(CIA_IMPACT_WEIGHTS.keys())}"
        )
    return label


def validate_probability(value: float, name: str = "probability") -> float:
    """Raise ``ValueError`` when *value* is outside [0, 1]."""
    if not (0.0 <= value <= 1.0):
        raise ValueError(f"{name} must be between 0 and 1, got {value}")
    return value


def validate_risk_score(score: float, name: str = "risk_score") -> float:
    """Raise ``ValueError`` when *score* is outside [0, 100]."""
    if not (0.0 <= score <= 100.0):
        raise ValueError(f"{name} must be between 0 and 100, got {score}")
    return score


# ---------------------------------------------------------------------------
# Rule / template structure validation
# ---------------------------------------------------------------------------

REQUIRED_RULE_FIELDS = {
    "id", "name", "category", "severity",
    "description", "detection", "risk_profile",
}

REQUIRED_TEMPLATE_FIELDS = {
    "id", "name", "category", "applies_to",
    "fix_strategy", "fix_template",
}


def validate_rule_dict(rule: dict[str, Any]) -> list[str]:
    """
    Validate a rule dictionary loaded from YAML.

    Returns
    -------
    list[str]
        A list of error messages; empty when the rule is valid.
    """
    errors: list[str] = []

    # Required fields
    missing = REQUIRED_RULE_FIELDS - set(rule.keys())
    if missing:
        errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

    # Severity
    if "severity" in rule:
        try:
            validate_severity(rule["severity"])
        except ValueError as exc:
            errors.append(str(exc))

    # Category
    if "category" in rule:
        try:
            validate_category(rule["category"])
        except ValueError as exc:
            errors.append(str(exc))

    # Detection block
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        errors.append("'detection' must be a mapping.")
    else:
        if "type" not in detection:
            errors.append("'detection.type' is required.")
        if "patterns" not in detection or not detection["patterns"]:
            errors.append("'detection.patterns' must be a non-empty list.")
        else:
            # Validate regex syntax
            for i, pattern in enumerate(detection.get("patterns", [])):
                try:
                    re.compile(pattern)
                except re.error as exc:
                    errors.append(f"Invalid regex at detection.patterns[{i}]: {exc}")

    # Risk profile
    rp = rule.get("risk_profile", {})
    if not isinstance(rp, dict):
        errors.append("'risk_profile' must be a mapping.")
    else:
        for field in ("likelihood_mean", "likelihood_std", "base_severity"):
            if field not in rp:
                errors.append(f"'risk_profile.{field}' is required.")

    return errors


def validate_template_dict(template: dict[str, Any]) -> list[str]:
    """
    Validate a template dictionary loaded from YAML.

    Returns
    -------
    list[str]
        A list of error messages; empty when the template is valid.
    """
    errors: list[str] = []

    missing = REQUIRED_TEMPLATE_FIELDS - set(template.keys())
    if missing:
        errors.append(f"Missing required fields: {', '.join(sorted(missing))}")

    if "applies_to" in template and not isinstance(template["applies_to"], list):
        errors.append("'applies_to' must be a list of rule IDs.")

    return errors


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def compute_content_hash(content: str) -> str:
    """Return the SHA-256 hex digest of *content*."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def sanitise_string(value: str, max_length: int = 1_000) -> str:
    """
    Strip leading/trailing whitespace and truncate to *max_length*.

    Safe to use on any user-supplied string before storing or displaying it.
    """
    return value.strip()[:max_length]


def is_placeholder_value(value: str) -> bool:
    """
    Return ``True`` when *value* looks like a placeholder (e.g. ``<secret>``
    or ``${MY_VAR}``), which should NOT be flagged as a hard-coded credential.
    """
    placeholder_patterns = [
        r"^\$\{[^}]+\}$",          # ${ENV_VAR}
        r"^<[^>]+>$",              # <placeholder>
        r"^%[A-Z_]+%$",            # %WINDOWS_VAR%
        r"^\*+$",                  # ****
        r"^(your|my|the)[-_]?",    # your_secret, my-key, etc.
        r"^(change|replace|todo)",  # change_me, replace_this
        r"^(example|sample|test|dummy|fake|placeholder)",
        r"^(xxx|yyy|zzz|aaa|bbb)",
    ]
    lower = value.strip().lower()
    for pat in placeholder_patterns:
        if re.search(pat, lower):
            return True
    return False
