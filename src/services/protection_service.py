"""
Protection Service
NIST CSF Function: PROTECT
Runs the Blue Team engine to generate and apply fixes.
"""
from typing import Dict, List, Tuple

from ..core.blue_team.remediator import BlueTeamRemediator
from ..models.config_model import ConfigFile
from ..models.fix_model import SecurityFix
from ..models.issue_model import SecurityIssue


class ProtectionService:
    """
    NIST PROTECT — Generates remediation fixes using the Blue Team engine.

    Provides fix generation, simulation of remediation,
    and optional application of fixes to config files.
    """

    def __init__(self, templates_dir: str = None):
        self.remediator = BlueTeamRemediator(templates_dir=templates_dir)

    def generate_fixes(self, issues: List[SecurityIssue]) -> List[SecurityFix]:
        """
        Generate fix recommendations for all detected issues.

        Args:
            issues: List of SecurityIssue from DetectionService

        Returns:
            List of SecurityFix objects
        """
        return self.remediator.remediate(issues)

    def simulate_remediation(
        self,
        issues: List[SecurityIssue],
        fixes: List[SecurityFix],
    ) -> List[SecurityIssue]:
        """
        Return the issues that would remain after applying fixes.

        Used to compare before/after risk in Monte Carlo simulation.

        Args:
            issues: All detected issues
            fixes:  All generated fixes

        Returns:
            Remaining issues after remediation
        """
        return self.remediator.simulate_remediation(issues, fixes)

    def apply_fixes(
        self,
        config: ConfigFile,
        fixes: List[SecurityFix],
    ) -> Tuple[ConfigFile, List[SecurityFix]]:
        """
        Apply selected fixes to a configuration file.

        Args:
            config: Original ConfigFile
            fixes:  Fixes to apply

        Returns:
            (modified_config, list_of_applied_fixes)
        """
        return self.remediator.apply_fixes(config, fixes)

    def get_summary(self, fixes: List[SecurityFix]) -> Dict:
        """Get summary statistics for generated fixes."""
        return self.remediator.get_summary(fixes)
