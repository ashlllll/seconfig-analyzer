"""
Template Loader compatibility wrapper.

This module exists so tests and legacy imports can use:
    from templates.template_loader import TemplateLoader
"""
import os
from typing import Any, Dict, List, Optional

import yaml


class TemplateLoader:
    """
    Legacy-style template loader backed by TemplateEngine.
    """

    def __init__(self, templates_dir: str = None):
        if templates_dir is None:
            base = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(
                base, "..", "..", "data", "templates_catalog"
            )
        self.templates_dir = os.path.abspath(templates_dir)
        self._templates: Optional[List[Dict[str, Any]]] = None

    def load_all_templates(self) -> List[Dict[str, Any]]:
        """Return all loaded templates as a list."""
        if self._templates is not None:
            return self._templates

        if not os.path.exists(self.templates_dir):
            raise FileNotFoundError(f"Templates directory not found: {self.templates_dir}")

        templates: List[Dict[str, Any]] = []
        yaml_files = [
            file_name
            for file_name in os.listdir(self.templates_dir)
            if file_name.endswith(".yaml") or file_name.endswith(".yml")
        ]

        for file_name in sorted(yaml_files):
            file_path = os.path.join(self.templates_dir, file_name)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    for doc in yaml.safe_load_all(f):
                        if not doc:
                            continue
                        templates.extend(doc.get("templates", []))
            except (OSError, yaml.YAMLError):
                # Keep behavior tolerant: skip malformed files
                continue

        self._templates = templates
        return self._templates

    def find_template(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Find a template that applies to the given rule ID."""
        for template in self.load_all_templates():
            if rule_id in template.get("applies_to", []):
                return template
        return None
