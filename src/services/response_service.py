"""
Response Service
NIST CSF Function: RESPOND
Generates analysis reports from detected issues, fixes, and simulation results.
"""
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from ..models.config_model import ConfigFile
from ..models.fix_model import SecurityFix
from ..models.issue_model import SecurityIssue
from ..models.report_model import AnalysisReport, ExecutiveSummary
from ..models.risk_model import SimulationResult


class ResponseService:
    """
    NIST RESPOND — Assembles the full AnalysisReport.

    Combines all outputs from the analysis pipeline:
        - Asset inventory (Identify)
        - Detected issues (Detect)
        - Generated fixes (Protect)
        - Risk simulation (Simulate)
    into a single structured report ready for display and export.
    """

    def generate_report(
        self,
        config_file: ConfigFile,
        issues: List[SecurityIssue],
        fixes: List[SecurityFix],
        simulation_result: Optional[SimulationResult] = None,
        assets: Optional[Dict] = None,
    ) -> AnalysisReport:
        """
        Build a complete AnalysisReport.

        Args:
            config_file:       Parsed configuration file
            issues:            Detected security issues
            fixes:             Generated fix recommendations
            simulation_result: Monte Carlo results (optional)
            assets:            Identified assets (optional)

        Returns:
            AnalysisReport object
        """
        # Group issues
        issues_by_severity = self._group_by_severity(issues)
        issues_by_category = self._group_by_category(issues)

        # Risk scores
        initial_risk = (
            simulation_result.before_remediation.mean
            if simulation_result else self._deterministic_risk(issues)
        )
        final_risk = (
            simulation_result.after_remediation.mean
            if simulation_result else self._deterministic_risk_after(issues, fixes)
        )
        risk_reduction_pct = (
            ((initial_risk - final_risk) / initial_risk * 100)
            if initial_risk > 0 else 0.0
        )

        # Fix counts
        auto_fixable = sum(1 for f in fixes if f.fix_type == "automated")
        manual_count = sum(1 for f in fixes if f.fix_type == "manual")

        # NIST coverage
        nist_coverage = self._nist_coverage(issues)

        # Executive summary
        executive_summary = self._build_executive_summary(
            issues=issues,
            issues_by_severity=issues_by_severity,
            fixes=fixes,
            initial_risk=initial_risk,
            final_risk=final_risk,
            risk_reduction_pct=risk_reduction_pct,
        )

        # Recommendations
        recommendations = self._generate_recommendations(
            issues, fixes, simulation_result
        )

        return AnalysisReport(
            report_id=self._generate_report_id(),
            generated_at=datetime.now(),
            config_file=config_file,
            executive_summary=executive_summary,
            issues=issues,
            issues_by_severity=issues_by_severity,
            issues_by_category=issues_by_category,
            fixes=fixes,
            auto_fixable_count=auto_fixable,
            manual_fix_count=manual_count,
            initial_risk_score=round(initial_risk, 2),
            final_risk_score=round(final_risk, 2),
            risk_reduction_percentage=round(risk_reduction_pct, 2),
            simulation_result=simulation_result,
            nist_coverage=nist_coverage,
            recommendations=recommendations,
        )

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _build_executive_summary(
        self,
        issues: List[SecurityIssue],
        issues_by_severity: Dict[str, List[SecurityIssue]],
        fixes: List[SecurityFix],
        initial_risk: float,
        final_risk: float,
        risk_reduction_pct: float,
    ) -> ExecutiveSummary:
        """Build the executive summary section."""
        top_issues = sorted(
            issues,
            key=lambda x: x.severity_weight,
            reverse=True,
        )[:3]

        top_issue_titles = [i.title for i in top_issues]

        auto_fixable = sum(1 for f in fixes if f.fix_type == "automated")
        manual_count = sum(1 for f in fixes if f.fix_type == "manual")

        # Key recommendation based on most severe issue
        key_rec = (
            f"Address {len(issues_by_severity.get('critical', []))} critical "
            f"issue(s) immediately before any deployment."
            if issues_by_severity.get("critical")
            else "Review and apply all generated fixes to reduce configuration risk."
        )

        return ExecutiveSummary(
            total_issues=len(issues),
            critical_count=len(issues_by_severity.get("critical", [])),
            high_count=len(issues_by_severity.get("high", [])),
            medium_count=len(issues_by_severity.get("medium", [])),
            low_count=len(issues_by_severity.get("low", [])),
            initial_risk_score=round(initial_risk, 2),
            final_risk_score=round(final_risk, 2),
            risk_reduction_percentage=round(risk_reduction_pct, 2),
            auto_fixable_count=auto_fixable,
            manual_fix_count=manual_count,
            top_issues=top_issue_titles,
            key_recommendation=key_rec,
        )

    def _group_by_severity(
        self, issues: List[SecurityIssue]
    ) -> Dict[str, List[SecurityIssue]]:
        """Group issues by severity."""
        groups: Dict[str, List[SecurityIssue]] = {
            "critical": [], "high": [], "medium": [], "low": [], "info": []
        }
        for issue in issues:
            if issue.severity in groups:
                groups[issue.severity].append(issue)
        return groups

    def _group_by_category(
        self, issues: List[SecurityIssue]
    ) -> Dict[str, List[SecurityIssue]]:
        """Group issues by category."""
        groups: Dict[str, List[SecurityIssue]] = {
            "credentials": [], "encryption": [],
            "access_control": [], "logging": [], "baseline": []
        }
        for issue in issues:
            if issue.category in groups:
                groups[issue.category].append(issue)
        return groups

    def _nist_coverage(self, issues: List[SecurityIssue]) -> Dict[str, int]:
        """Count issues per NIST CSF function."""
        coverage = {
            "IDENTIFY": 0, "PROTECT": 0,
            "DETECT": 0, "RESPOND": 0, "RECOVER": 0,
        }
        for issue in issues:
            if issue.nist_function in coverage:
                coverage[issue.nist_function] += 1
        return coverage

    def _generate_recommendations(
        self,
        issues: List[SecurityIssue],
        fixes: List[SecurityFix],
        simulation_result: Optional[SimulationResult],
    ) -> List[str]:
        """Generate prioritised recommendations."""
        recs = []

        critical = [i for i in issues if i.severity == "critical"]
        if critical:
            recs.append(
                f"IMMEDIATE: Remediate {len(critical)} critical issue(s) before "
                f"any production deployment."
            )

        auto_fixes = [f for f in fixes if f.fix_type == "automated" and
                      f.validation_status == "validated"]
        if auto_fixes:
            recs.append(
                f"Apply {len(auto_fixes)} automated fix(es) — these can be "
                f"applied immediately with low risk."
            )

        manual_fixes = [f for f in fixes if f.fix_type == "manual"]
        if manual_fixes:
            recs.append(
                f"Review {len(manual_fixes)} manual remediation guidance item(s) "
                f"that require human judgement."
            )

        if simulation_result and simulation_result.risk_reduction_percentage > 50:
            recs.append(
                f"Applying all fixes is projected to reduce risk by "
                f"{simulation_result.risk_reduction_percentage:.1f}% "
                f"(Monte Carlo, 95% CI: "
                f"[{simulation_result.confidence_interval[0]:.1f}, "
                f"{simulation_result.confidence_interval[1]:.1f}])."
            )

        if not recs:
            recs.append(
                "No critical issues detected. Continue following security "
                "best practices and schedule regular reviews."
            )

        return recs

    def _deterministic_risk(self, issues: List[SecurityIssue]) -> float:
        """Fallback deterministic risk when simulation is unavailable."""
        if not issues:
            return 0.0
        total = sum(i.risk_score for i in issues if i.risk_score)
        max_possible = len(issues) * 10.0
        return round((total / max_possible) * 100, 2) if max_possible else 0.0

    def _deterministic_risk_after(
        self,
        issues: List[SecurityIssue],
        fixes: List[SecurityFix],
    ) -> float:
        """Estimate post-fix deterministic risk."""
        fixed_ids = {f.issue_id for f in fixes if f.validation_status == "validated"}
        remaining = [i for i in issues if i.issue_id not in fixed_ids]
        return self._deterministic_risk(remaining)

    def _generate_report_id(self) -> str:
        """Generate a unique report ID."""
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        short_uuid = str(uuid.uuid4())[:6].upper()
        return f"RPT-{timestamp}-{short_uuid}"
