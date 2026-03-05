"""
Analysis Service
Main orchestrator that coordinates all NIST CSF service components
to run the complete SecConfig Analyzer pipeline.
"""
from typing import Dict, List, Optional, Tuple

from ..models.config_model import ConfigFile
from ..models.fix_model import SecurityFix
from ..models.issue_model import SecurityIssue
from ..models.report_model import AnalysisReport
from ..parsers.parser_factory import ParserFactory
from .identification_service import IdentificationService
from .detection_service import DetectionService
from .protection_service import ProtectionService
from .simulation_service import SimulationService
from .response_service import ResponseService


class AnalysisService:
    """
    Main orchestrator for the SecConfig Analyzer pipeline.

    Coordinates the full NIST CSF workflow:

        IDENTIFY  → IdentificationService   (asset discovery)
        DETECT    → DetectionService        (Red Team analysis)
        PROTECT   → ProtectionService       (Blue Team remediation)
        SIMULATE  → SimulationService       (Monte Carlo risk)
        RESPOND   → ResponseService         (report generation)

    Usage:
        service = AnalysisService()
        report  = service.run_full_analysis(config_file)
    """

    def __init__(
        self,
        rules_dir: str = None,
        templates_dir: str = None,
        simulation_iterations: int = 10000,
        simulation_seed: int = 42,
    ):
        self.identification = IdentificationService()
        self.detection = DetectionService(rules_dir=rules_dir)
        self.protection = ProtectionService(templates_dir=templates_dir)
        self.simulation = SimulationService(
            iterations=simulation_iterations,
            seed=simulation_seed,
        )
        self.response = ResponseService()

    # ── Main Pipeline ─────────────────────────────────────────────────────────

    def run_full_analysis(self, config_file: ConfigFile) -> AnalysisReport:
        """
        Execute the complete analysis pipeline on a config file.

        Steps:
            1. IDENTIFY  — discover assets
            2. DETECT    — run Red Team analysis
            3. SIMULATE  — calculate initial risk
            4. PROTECT   — generate Blue Team fixes
            5. SIMULATE  — calculate post-remediation risk
            6. RESPOND   — assemble the report

        Args:
            config_file: Parsed ConfigFile object

        Returns:
            Complete AnalysisReport
        """
        # 1. IDENTIFY
        assets = self.identification.identify_assets(config_file)

        # 2. DETECT
        issues = self.detection.detect_vulnerabilities(config_file)

        # 3. PROTECT
        fixes = self.protection.generate_fixes(issues)
        issues_after = self.protection.simulate_remediation(issues, fixes)

        # 4. SIMULATE (Monte Carlo before vs after)
        simulation_result = self.simulation.run_monte_carlo(
            issues_before=issues,
            issues_after=issues_after,
        )

        # 5. RESPOND
        report = self.response.generate_report(
            config_file=config_file,
            issues=issues,
            fixes=fixes,
            simulation_result=simulation_result,
            assets=assets,
        )

        return report

    # ── Partial Operations ────────────────────────────────────────────────────

    def parse_config(self, content: str, file_name: str) -> ConfigFile:
        """
        Parse a raw config string into a ConfigFile object.

        Args:
            content:   Raw file content
            file_name: Original file name (used to detect type)

        Returns:
            ConfigFile object
        """
        file_type = ParserFactory.get_file_type_from_name(file_name)
        parser = ParserFactory.get_parser(file_type)
        return parser.parse(content, file_name)

    def detect_only(self, config_file: ConfigFile) -> List[SecurityIssue]:
        """
        Run only the Red Team detection step.

        Args:
            config_file: Parsed ConfigFile

        Returns:
            List of SecurityIssue objects
        """
        return self.detection.detect_vulnerabilities(config_file)

    def fix_only(
        self,
        issues: List[SecurityIssue],
    ) -> List[SecurityFix]:
        """
        Run only the Blue Team fix generation step.

        Args:
            issues: Detected issues

        Returns:
            List of SecurityFix objects
        """
        return self.protection.generate_fixes(issues)

    def apply_selected_fixes(
        self,
        config_file: ConfigFile,
        fixes: List[SecurityFix],
    ) -> Tuple[ConfigFile, List[SecurityFix]]:
        """
        Apply a user-selected subset of fixes to the config file.

        Args:
            config_file: Original ConfigFile
            fixes:       Fixes selected by the user

        Returns:
            (modified_config, applied_fixes)
        """
        return self.protection.apply_fixes(config_file, fixes)

    def get_asset_summary(self, config_file: ConfigFile) -> Dict:
        """
        Return asset identification summary for the sidebar/overview.

        Args:
            config_file: Parsed ConfigFile

        Returns:
            Dictionary of category → count
        """
        assets = self.identification.identify_assets(config_file)
        return self.identification.get_asset_summary(assets)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def rules_loaded(self) -> int:
        """Number of Red Team rules currently loaded."""
        return self.detection.rules_loaded

    @property
    def supported_formats(self) -> List[str]:
        """Supported config file formats."""
        return ParserFactory.supported_extensions()
