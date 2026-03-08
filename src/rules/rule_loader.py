"""
Rule Loader compatibility wrapper.

This module keeps legacy imports working:
    from src.rules.rule_loader import RuleLoader
"""
import os
from typing import Any, Dict, List, Optional

import yaml


class RuleLoader:
    """Load rule definitions from YAML files under data/rules_catalog."""

    def __init__(self, rules_dir: Optional[str] = None):
        if rules_dir is None:
            base = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(base, "..", "..", "data", "rules_catalog")
        self.rules_dir = os.path.abspath(rules_dir)
        self._rules: Optional[List[Dict[str, Any]]] = None

    def load_all_rules(self) -> List[Dict[str, Any]]:
        """Load and return all rules as dictionaries."""
        if self._rules is not None:
            return self._rules

        if not os.path.exists(self.rules_dir):
            raise FileNotFoundError(f"Rules directory not found: {self.rules_dir}")

        yaml_files = [
            file_name
            for file_name in os.listdir(self.rules_dir)
            if file_name.endswith(".yaml") or file_name.endswith(".yml")
        ]

        rules: List[Dict[str, Any]] = []
        for file_name in sorted(yaml_files):
            file_path = os.path.join(self.rules_dir, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    raw = f.read()
                    normalized = raw.replace("\\'", "''")
                    for doc in yaml.safe_load_all(normalized):
                        if not doc:
                            continue
                        rules.extend(doc.get("rules", []))
            except (OSError, yaml.YAMLError):
                # Keep behavior tolerant for malformed files.
                continue

        self._rules = rules
        return self._rules
