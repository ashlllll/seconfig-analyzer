"""
Template Engine
Loads fix templates from YAML and renders them for specific issues.
"""
import os
import re
from typing import Any, Dict, List, Optional

import yaml


class TemplateLoadError(Exception):
    """Raised when a template file cannot be loaded."""
    pass


class TemplateEngine:
    """
    Loads fix templates from YAML catalog and renders them.

    Templates are deterministic — given the same issue, the same
    fix is always generated. No AI is involved in this process.
    """

    def __init__(self, templates_dir: str = None):
        """
        Initialize and load all fix templates.

        Args:
            templates_dir: Path to templates catalog directory.
                           Defaults to data/templates_catalog.
        """
        if templates_dir is None:
            base = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(
                base, "..", "..", "..", "data", "templates_catalog"
            )

        self.templates_dir = os.path.abspath(templates_dir)
        self.templates: Dict[str, Dict[str, Any]] = {}  # keyed by template_id

        self._load_all_templates()

    # ── Loading ───────────────────────────────────────────────────────────────

    def _load_all_templates(self):
        """Load all YAML template files from the templates directory."""
        if not os.path.exists(self.templates_dir):
            # Templates dir may not exist yet — not a fatal error
            return

        yaml_files = [
            f for f in os.listdir(self.templates_dir)
            if f.endswith(".yaml") or f.endswith(".yml")
        ]

        for file_name in sorted(yaml_files):
            file_path = os.path.join(self.templates_dir, file_name)
            self._load_template_file(file_path)

    def _load_template_file(self, file_path: str):
        """Load a single YAML template file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            if not data or "templates" not in data:
                return

            for template in data["templates"]:
                template_id = template.get("id")
                if template_id:
                    self.templates[template_id] = template

        except (yaml.YAMLError, OSError):
            pass  # Skip malformed template files

    # ── Lookup ────────────────────────────────────────────────────────────────

    def get_template(self, template_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a template by its ID.

        Args:
            template_id: e.g. 'CRED-FIX-001'

        Returns:
            Template dictionary or None if not found
        """
        return self.templates.get(template_id)

    def find_template_for_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Find a template that applies to a given rule ID.

        Args:
            rule_id: e.g. 'CRED-001'

        Returns:
            Matching template dictionary or None
        """
        for template in self.templates.values():
            applies_to = template.get("applies_to", [])
            if rule_id in applies_to:
                return template
        return None

    # ── Rendering ─────────────────────────────────────────────────────────────

    def render(
        self,
        template: Dict[str, Any],
        variables: Dict[str, str],
    ) -> str:
        """
        Render a fix template by substituting variables.

        Uses simple {{variable_name}} substitution.

        Args:
            template:  Template dictionary
            variables: Key-value pairs to substitute

        Returns:
            Rendered fix code string
        """
        fix_template = template.get("fix_template", "")

        # Replace {{variable}} placeholders
        def replacer(match):
            var_name = match.group(1).strip()
            return variables.get(var_name, match.group(0))

        rendered = re.sub(r'\{\{(\w+)\}\}', replacer, fix_template)
        return rendered.strip()

    def extract_variables(
        self,
        template: Dict[str, Any],
        vulnerable_code: str,
    ) -> Dict[str, str]:
        """
        Extract variable values from vulnerable code for template rendering.

        For example, from 'DATABASE_PASSWORD=admin123' extracts:
            original_key   = 'DATABASE_PASSWORD'
            original_value = 'admin123'
            env_var_name   = 'DATABASE_PASSWORD'

        Args:
            template:       Template dictionary
            vulnerable_code: The vulnerable line of code

        Returns:
            Dictionary of variable name → value
        """
        variables: Dict[str, str] = {}

        # Extract KEY=VALUE from the vulnerable code
        kv_match = re.match(
            r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*)$',
            vulnerable_code.strip()
        )

        if kv_match:
            key = kv_match.group(1).strip()
            value = kv_match.group(2).strip().strip('"').strip("'")
            variables["original_key"] = key
            variables["original_value"] = value
            variables["env_var_name"] = key

        # Add any defaults from template variable definitions
        for var_def in template.get("variables", []):
            var_name = var_def.get("name", "")
            default = var_def.get("default", "")

            if var_name not in variables:
                # Resolve default if it references another variable
                if "{{" in default:
                    def replacer(match):
                        ref = match.group(1).strip()
                        return variables.get(ref, "")
                    default = re.sub(r'\{\{(\w+)\}\}', replacer, default)
                variables[var_name] = default

        return variables

    @property
    def template_count(self) -> int:
        """Return total number of loaded templates."""
        return len(self.templates)

    def get_template_ids(self) -> List[str]:
        """Return list of all loaded template IDs."""
        return list(self.templates.keys())
