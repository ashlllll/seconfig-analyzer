"""
Red Team Analyzer
Main entry point for the Red Team security analysis engine.
"""
from typing import Dict, List, Optional

from .rule_engine import RuleEngine
from ...models.config_model import ConfigFile
from ...models.issue_model import SecurityIssue


class RedTeamAnalyzer:
    """
    Main Red Team analyzer — orchestrates rule loading and analysis.

    This is the primary interface used by the DetectionService.
    It is deterministic: the same config always produces the same findings.

    Usage:
        analyzer = RedTeamAnalyzer()
        issues = analyzer.analyze(config_file)
    """

    def __init__(self, rules_dir: str = None):
        """
        Initialize the analyzer and load all security rules.

        Args:
            rules_dir: Optional path to rules directory.
                       Defaults to data/rules_catalog.
        """
        self.rule_engine = RuleEngine(rules_dir=rules_dir)

    def analyze(self, config: ConfigFile) -> List[SecurityIssue]:
        """
        Run the full Red Team analysis on a configuration file.

        Args:
            config: A parsed ConfigFile object

        Returns:
            List of SecurityIssue objects sorted by severity (critical first)
        """
        if not config.is_valid:
            # Cannot analyze an invalid/unparseable config
            return []

        issues = self.rule_engine.analyze(config)
        return issues

    def get_summary(self, issues: List[SecurityIssue]) -> Dict:
        """
        Generate a summary dictionary from a list of issues.

        Args:
            issues: List of SecurityIssue objects

        Returns:
            Dictionary with counts by severity and category
        """
        summary = {
            "total": len(issues),
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
            "by_category": {
                "credentials": 0,
                "encryption": 0,
                "access_control": 0,
                "logging": 0,
                "baseline": 0,
            },
            "by_nist_function": {
                "IDENTIFY": 0,
                "PROTECT": 0,
                "DETECT": 0,
                "RESPOND": 0,
                "RECOVER": 0,
            },
        }

        for issue in issues:
            # Count by severity
            if issue.severity in summary["by_severity"]:
                summary["by_severity"][issue.severity] += 1

            # Count by category
            if issue.category in summary["by_category"]:
                summary["by_category"][issue.category] += 1

            # Count by NIST function
            if issue.nist_function in summary["by_nist_function"]:
                summary["by_nist_function"][issue.nist_function] += 1

        return summary

    def group_by_severity(
        self, issues: List[SecurityIssue]
    ) -> Dict[str, List[SecurityIssue]]:
        """Group issues by severity level."""
        grouped: Dict[str, List[SecurityIssue]] = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }
        for issue in issues:
            if issue.severity in grouped:
                grouped[issue.severity].append(issue)
        return grouped

    def group_by_category(
        self, issues: List[SecurityIssue]
    ) -> Dict[str, List[SecurityIssue]]:
        """Group issues by category."""
        grouped: Dict[str, List[SecurityIssue]] = {
            "credentials": [],
            "encryption": [],
            "access_control": [],
            "logging": [],
            "baseline": [],
        }
        for issue in issues:
            if issue.category in grouped:
                grouped[issue.category].append(issue)
        return grouped

    @property
    def rules_loaded(self) -> int:
        """Return number of rules loaded."""
        return self.rule_engine.rule_count

    @property
    def rule_ids(self) -> List[str]:
        """Return list of loaded rule IDs."""
        return self.rule_engine.get_rule_ids()
