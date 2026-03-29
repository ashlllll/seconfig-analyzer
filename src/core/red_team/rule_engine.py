"""
Rule Engine
Loads security rules from YAML and applies them to parsed config files.
"""
import logging
import os
import uuid
from datetime import datetime
from typing import Any, Dict, List, Set, Tuple

import yaml

from .matcher import Matcher, MatchResult
from ...models.config_model import ConfigFile
from ...models.issue_model import SecurityIssue
from ...models.risk_model import RiskProfile

log = logging.getLogger(__name__)


class RuleLoadError(Exception):
    """Raised when a rule file cannot be loaded or parsed."""
    pass


class RuleEngine:
    """
    Loads YAML rule definitions and applies them to configuration files.

    This is the core of the Red Team analyzer. It is deterministic —
    the same input always produces the same output.
    """

    def __init__(self, rules_dir: str = None):
        """
        Initialize the rule engine and load all rules.

        Args:
            rules_dir: Path to the rules catalog directory.
                       Defaults to 'data/rules_catalog' relative to project root.
        """
        if rules_dir is None:
            # Default: walk up from this file to find data/rules_catalog
            base = os.path.dirname(os.path.abspath(__file__))
            rules_dir = os.path.join(base, "..", "..", "..", "data", "rules_catalog")

        self.rules_dir = os.path.abspath(rules_dir)
        self.rules: List[Dict[str, Any]] = []
        self.matcher = Matcher()

        self._load_all_rules()

    # ── Rule Loading ──────────────────────────────────────────────────────────

    def _load_all_rules(self):
        """Load all YAML rule files from the rules directory."""
        if not os.path.exists(self.rules_dir):
            raise RuleLoadError(f"Rules directory not found: {self.rules_dir}")

        yaml_files = [
            f for f in os.listdir(self.rules_dir)
            if f.endswith(".yaml") or f.endswith(".yml")
        ]

        if not yaml_files:
            raise RuleLoadError(f"No rule files found in: {self.rules_dir}")

        for file_name in sorted(yaml_files):
            file_path = os.path.join(self.rules_dir, file_name)
            try:
                rules = self._load_rule_file(file_path)
                self.rules.extend(rules)
                log.debug("Loaded %d rule(s) from '%s'.", len(rules), file_name)
            except RuleLoadError as e:
                # A single bad file must not abort the entire catalog load.
                # Log a warning and continue so all valid rules are applied.
                log.warning("Skipping rule file '%s': %s", file_name, e)

    def _load_rule_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Load and parse a single YAML rule file.

        Args:
            file_path: Full path to the YAML rule file

        Returns:
            List of rule dictionaries
        """
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw = f.read()

            # Many catalog regex strings are single-quoted and use \'
            # which is invalid in YAML single-quoted scalars. Normalize it
            # to YAML's escaped single quote representation.
            normalized = raw.replace("\\'", "''")
            data = yaml.safe_load(normalized)

            if not data or "rules" not in data:
                return []

            return data["rules"]

        except yaml.YAMLError as e:
            raise RuleLoadError(f"Failed to parse rule file {file_path}: {e}")
        except OSError as e:
            raise RuleLoadError(f"Failed to read rule file {file_path}: {e}")

    # ── Analysis ──────────────────────────────────────────────────────────────

    def analyze(self, config: ConfigFile) -> List[SecurityIssue]:
        """
        Apply all loaded rules to a configuration file.

        FIX: Added deduplication so that a single vulnerable line cannot be
        reported more than once for the same category. Without this, a line
        like:
            DATABASE_PASSWORD=admin123
        could be flagged by both CRED-001 (Hard-coded Password) and CRED-004
        (Weak Secret Key), inflating the issue count and confusing users.

        Deduplication key: (line_number, category)
        — the same line can still be flagged by rules from DIFFERENT categories
        (e.g. a line that is both a credential issue and a baseline issue),
        but within a category only the highest-severity match is kept.

        Args:
            config: Parsed ConfigFile object

        Returns:
            List of SecurityIssue objects, sorted by severity
        """
        # Collect all raw findings first
        all_findings: List[Tuple[MatchResult, Dict[str, Any]]] = []

        for rule in self.rules:
            # Check if rule applies to this file type
            detection = rule.get("detection", {})
            apply_to = detection.get("apply_to", ["env", "yaml", "json"])

            if config.file_type not in apply_to:
                continue

            # Get patterns and exclusions
            patterns = detection.get("patterns", [])
            exclusions = rule.get("exclusions", [])
            exclusion_patterns = [e.get("pattern", "") for e in exclusions if e]

            # Scan the raw content
            matches = self.matcher.scan_content(
                content=config.raw_content,
                patterns=patterns,
                exclusion_patterns=exclusion_patterns,
            )

            for match in matches:
                all_findings.append((match, rule))

        # FIX: Deduplicate — within each (line_number, category) bucket,
        # keep only the finding from the highest-severity rule.
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        # Map (line_number, category) → (severity_weight, match, rule)
        best: Dict[Tuple[int, str], Tuple[int, MatchResult, Dict]] = {}

        for match, rule in all_findings:
            key = (match.line_number, rule.get("category", "baseline"))
            sev_weight = severity_order.get(rule.get("severity", "info"), 99)

            if key not in best or sev_weight < best[key][0]:
                best[key] = (sev_weight, match, rule)

        # Build SecurityIssue objects from deduplicated findings
        issues: List[SecurityIssue] = []
        for _sev_weight, match, rule in best.values():
            issue = self._create_issue(match, rule, config)
            issues.append(issue)

        # Sort by severity weight (critical first)
        issues.sort(key=lambda x: severity_order.get(x.severity, 99))

        return issues

    # ── Issue Creation ────────────────────────────────────────────────────────

    def _create_issue(
        self,
        match: MatchResult,
        rule: Dict[str, Any],
        config: ConfigFile,
    ) -> SecurityIssue:
        """
        Convert a MatchResult and rule definition into a SecurityIssue.

        Args:
            match:  The regex match result
            rule:   The rule dictionary from YAML
            config: The source config file

        Returns:
            SecurityIssue object
        """
        # Build unique issue ID
        issue_id = self._generate_issue_id(rule["id"])

        # Build risk profile from rule definition
        risk_profile = self._build_risk_profile(rule)

        # Get context lines
        lines = config.raw_content.splitlines()
        context_before, context_after = self.matcher.get_context(
            lines=lines,
            line_number=match.line_number,
        )

        # Extract remediation info
        remediation = rule.get("remediation", {})

        return SecurityIssue(
            issue_id=issue_id,
            rule_id=rule.get("id", "UNKNOWN"),
            rule_name=rule.get("name", "Unknown Rule"),
            category=rule.get("category", "baseline"),
            severity=rule.get("severity", "medium"),
            cvss_score=float(rule.get("cvss_score", 5.0)),
            title=rule.get("name", "Security Issue"),
            description=rule.get("description", "").strip(),
            file_name=config.file_name,
            line_number=match.line_number,
            column_start=match.column_start,
            column_end=match.column_end,
            vulnerable_code=match.vulnerable_code,
            context_before=context_before,
            context_after=context_after,
            risk_profile=risk_profile,
            remediation_hint=remediation.get("hint", ""),
            recommended_fix=remediation.get("example_fix", ""),
            template_id=remediation.get("template_id"),
            nist_function=rule.get("nist_function", "PROTECT"),
            nist_category=rule.get("nist_category", ""),
            cwe_id=rule.get("cwe_id", ""),
            owasp_category=rule.get("owasp_category"),
            references=rule.get("references", []),
            detected_at=datetime.now(),
        )

    def _build_risk_profile(self, rule: Dict[str, Any]) -> RiskProfile:
        """
        Build a RiskProfile from a rule's risk_profile definition.

        Args:
            rule: Rule dictionary

        Returns:
            RiskProfile object
        """
        rp = rule.get("risk_profile", {})

        return RiskProfile(
            base_severity=float(rp.get("base_severity", 5.0)),
            exploitability=float(rp.get("exploitability", 0.5)),
            impact_confidentiality=rp.get("impact_confidentiality", "medium"),
            impact_integrity=rp.get("impact_integrity", "medium"),
            impact_availability=rp.get("impact_availability", "low"),
            likelihood_mean=float(rp.get("likelihood_mean", 0.5)),
            likelihood_std=float(rp.get("likelihood_std", 0.15)),
            distribution_type=rp.get("distribution_type", "beta"),
        )

    def _generate_issue_id(self, rule_id: str) -> str:
        """Generate a unique issue ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        short_uuid = str(uuid.uuid4())[:6]
        return f"{rule_id}-{timestamp}-{short_uuid}"

    # ── Utilities ─────────────────────────────────────────────────────────────

    @property
    def rule_count(self) -> int:
        """Return total number of loaded rules."""
        return len(self.rules)

    def get_rule_ids(self) -> List[str]:
        """Return list of all loaded rule IDs."""
        return [rule.get("id", "UNKNOWN") for rule in self.rules]

    def get_rules_by_category(self, category: str) -> List[Dict]:
        """Return rules filtered by category."""
        return [r for r in self.rules if r.get("category") == category]