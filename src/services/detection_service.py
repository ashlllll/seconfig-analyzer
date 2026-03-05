"""
Detection Service
NIST CSF Function: DETECT
Runs the Red Team analysis to detect security vulnerabilities.
"""
from typing import Dict, List

from ..core.red_team.analyzer import RedTeamAnalyzer
from ..models.config_model import ConfigFile
from ..models.issue_model import SecurityIssue


class DetectionService:
    """
    NIST DETECT — Runs the Red Team analyzer to find vulnerabilities.

    Wraps the RedTeamAnalyzer and provides grouped results
    ready for display in the dashboard.
    """

    def __init__(self, rules_dir: str = None):
        self.analyzer = RedTeamAnalyzer(rules_dir=rules_dir)

    def detect_vulnerabilities(self, config: ConfigFile) -> List[SecurityIssue]:
        """
        Run Red Team analysis on a configuration file.

        Args:
            config: Parsed ConfigFile object

        Returns:
            List of SecurityIssue objects sorted by severity
        """
        if not config.is_valid:
            return []

        return self.analyzer.analyze(config)

    def group_by_severity(
        self, issues: List[SecurityIssue]
    ) -> Dict[str, List[SecurityIssue]]:
        """Group issues by severity level."""
        return self.analyzer.group_by_severity(issues)

    def group_by_category(
        self, issues: List[SecurityIssue]
    ) -> Dict[str, List[SecurityIssue]]:
        """Group issues by category."""
        return self.analyzer.group_by_category(issues)

    def get_summary(self, issues: List[SecurityIssue]) -> Dict:
        """Get summary statistics for detected issues."""
        return self.analyzer.get_summary(issues)

    @property
    def rules_loaded(self) -> int:
        """Number of rules currently loaded."""
        return self.analyzer.rules_loaded
