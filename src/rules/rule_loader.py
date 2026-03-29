"""
Rule Loader
Provides a lightweight interface for loading and inspecting security rules
from the YAML catalog. Used independently of RuleEngine where only rule
metadata is needed (e.g. tests, validation scripts, UI rule listings).

Note: RuleEngine has its own internal loading logic for performance reasons
(it pre-compiles regex patterns). This module is the canonical source for
rule dictionaries as plain data — use it when you need rules as dicts,
not as compiled engine state.
"""
import os
from typing import Any, Dict, List, Optional

import yaml


class RuleLoader:
    """Load rule definitions from YAML files under data/rules_catalog."""

    # Expected rule categories — used for validation
    VALID_CATEGORIES = {
        "credentials",
        "encryption",
        "access_control",
        "logging",
        "baseline",
    }

    # Expected severity levels
    VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

    def __init__(self, rules_dir: Optional[str] = None):
        if rules_dir is None:
            base = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(base, "..", "..", "data", "rules_catalog")
        self.rules_dir = os.path.abspath(rules_dir)
        self._rules: Optional[List[Dict[str, Any]]] = None

    def load_all_rules(self) -> List[Dict[str, Any]]:
        """
        Load and return all rules as plain dictionaries.

        Rules are cached after the first load — call invalidate_cache()
        if you need to reload from disk.

        Returns:
            List of rule dicts, one per rule across all catalog files.

        Raises:
            FileNotFoundError: if the rules directory does not exist.
        """
        if self._rules is not None:
            return self._rules

        if not os.path.exists(self.rules_dir):
            raise FileNotFoundError(
                f"Rules directory not found: {self.rules_dir}"
            )

        yaml_files = sorted(
            f for f in os.listdir(self.rules_dir)
            if f.endswith(".yaml") or f.endswith(".yml")
        )

        rules: List[Dict[str, Any]] = []
        for file_name in yaml_files:
            file_path = os.path.join(self.rules_dir, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    raw = f.read()
                # Normalize escaped single quotes in YAML single-quoted scalars
                normalized = raw.replace("\\'", "''")
                for doc in yaml.safe_load_all(normalized):
                    if not doc:
                        continue
                    rules.extend(doc.get("rules", []))
            except (OSError, yaml.YAMLError):
                # Tolerate individual bad files — log and continue
                continue

        self._rules = rules
        return self._rules

    def invalidate_cache(self) -> None:
        """Force rules to be reloaded from disk on the next call."""
        self._rules = None

    def get_rule_by_id(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Return a single rule dict by its ID, or None if not found.

        Args:
            rule_id: e.g. "CRED-001"
        """
        for rule in self.load_all_rules():
            if rule.get("id") == rule_id:
                return rule
        return None

    def get_rules_by_category(self, category: str) -> List[Dict[str, Any]]:
        """Return all rules belonging to a given category."""
        return [
            r for r in self.load_all_rules()
            if r.get("category") == category
        ]

    def validate_rules(self) -> Dict[str, List[str]]:
        """
        Validate all loaded rules and return a report of issues found.

        Checks:
        - Required fields present (id, name, category, severity, description,
          detection.patterns, risk_profile)
        - Category is one of the known values
        - Severity is one of the known values
        - detection.patterns is a non-empty list

        Returns:
            Dict mapping rule_id (or file position) to list of error strings.
            An empty dict means all rules are valid.
        """
        import re

        errors: Dict[str, List[str]] = {}

        for i, rule in enumerate(self.load_all_rules()):
            rule_id = rule.get("id", f"<rule #{i}>")
            rule_errors: List[str] = []

            # Required top-level fields
            for field in ("id", "name", "category", "severity", "description"):
                if not rule.get(field):
                    rule_errors.append(f"Missing required field: '{field}'")

            # Category validation
            cat = rule.get("category", "")
            if cat and cat not in self.VALID_CATEGORIES:
                rule_errors.append(
                    f"Unknown category '{cat}'. "
                    f"Expected one of: {sorted(self.VALID_CATEGORIES)}"
                )

            # Severity validation
            sev = rule.get("severity", "")
            if sev and sev not in self.VALID_SEVERITIES:
                rule_errors.append(
                    f"Unknown severity '{sev}'. "
                    f"Expected one of: {sorted(self.VALID_SEVERITIES)}"
                )

            # detection.patterns must be a non-empty list
            detection = rule.get("detection", {})
            patterns = detection.get("patterns", [])
            if not patterns:
                rule_errors.append("detection.patterns is empty or missing")
            else:
                # Validate each regex compiles successfully
                for pattern in patterns:
                    normalized = pattern.replace("(?i)", "")
                    try:
                        re.compile(normalized, re.IGNORECASE)
                    except re.error as e:
                        rule_errors.append(
                            f"Invalid regex in detection.patterns: "
                            f"'{pattern}' — {e}"
                        )

            # risk_profile must exist
            if not rule.get("risk_profile"):
                rule_errors.append("Missing risk_profile section")

            if rule_errors:
                errors[rule_id] = rule_errors

        return errors

    @property
    def rule_count(self) -> int:
        """Total number of loaded rules."""
        return len(self.load_all_rules())

    @property
    def rule_ids(self) -> List[str]:
        """List of all rule IDs."""
        return [r.get("id", "UNKNOWN") for r in self.load_all_rules()]

    @property
    def categories(self) -> Dict[str, int]:
        """Return a count of rules per category."""
        counts: Dict[str, int] = {}
        for rule in self.load_all_rules():
            cat = rule.get("category", "unknown")
            counts[cat] = counts.get(cat, 0) + 1
        return counts