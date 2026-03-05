"""
Analysis Report Data Model
The final output of a complete Red Team / Blue Team analysis session.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config_model import ConfigFile
from .issue_model import SecurityIssue
from .fix_model import SecurityFix
from .risk_model import SimulationResult


# ── Executive Summary ─────────────────────────────────────────────────────────

@dataclass
class ExecutiveSummary:
    """
    High-level summary of the analysis for non-expert stakeholders.
    Designed to communicate risk in plain language.
    """

    total_issues: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    initial_risk_score: float       # before remediation (0-100)
    final_risk_score: float         # after remediation (0-100)
    risk_reduction_percentage: float

    auto_fixable_count: int
    manual_fix_count: int

    top_issues: List[str] = field(default_factory=list)     # top 3 issue titles
    key_recommendations: List[str] = field(default_factory=list)

    @property
    def overall_risk_level(self) -> str:
        """Determine overall risk level from initial score."""
        if self.initial_risk_score >= 70:
            return "CRITICAL"
        elif self.initial_risk_score >= 40:
            return "HIGH"
        elif self.initial_risk_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_issues": self.total_issues,
            "by_severity": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "initial_risk_score": round(self.initial_risk_score, 2),
            "final_risk_score": round(self.final_risk_score, 2),
            "risk_reduction_percentage": round(self.risk_reduction_percentage, 2),
            "overall_risk_level": self.overall_risk_level,
            "auto_fixable_count": self.auto_fixable_count,
            "manual_fix_count": self.manual_fix_count,
            "top_issues": self.top_issues,
            "key_recommendations": self.key_recommendations,
        }


# ── Analysis Report ───────────────────────────────────────────────────────────

@dataclass
class AnalysisReport:
    """
    Complete analysis report combining Red Team, Blue Team, and simulation results.

    This is the primary output of the AnalysisService and is used
    by the Streamlit dashboard to render all pages.
    """

    # ── Report Identity ───────────────────────────────────────────────────────
    report_id: str
    generated_at: datetime

    # ── Input ─────────────────────────────────────────────────────────────────
    config_file: ConfigFile

    # ── Summary ───────────────────────────────────────────────────────────────
    executive_summary: ExecutiveSummary

    # ── Red Team Results ──────────────────────────────────────────────────────
    issues: List[SecurityIssue] = field(default_factory=list)
    issues_by_severity: Dict[str, List[SecurityIssue]] = field(default_factory=dict)
    issues_by_category: Dict[str, List[SecurityIssue]] = field(default_factory=dict)

    # ── Blue Team Results ─────────────────────────────────────────────────────
    fixes: List[SecurityFix] = field(default_factory=list)
    auto_fixable_count: int = 0
    manual_fix_count: int = 0

    # ── Risk Scores ───────────────────────────────────────────────────────────
    initial_risk_score: float = 0.0
    final_risk_score: float = 0.0
    risk_reduction_percentage: float = 0.0

    # ── Monte Carlo Results (optional) ────────────────────────────────────────
    simulation_result: Optional[SimulationResult] = None

    # ── NIST CSF Coverage ────────────────────────────────────────────────────
    nist_coverage: Dict[str, int] = field(default_factory=dict)

    # ── Recommendations ───────────────────────────────────────────────────────
    recommendations: List[str] = field(default_factory=list)

    # ── Optional AI Explanation ───────────────────────────────────────────────
    ai_explanation: Optional[str] = None

    @property
    def has_simulation(self) -> bool:
        """Return True if Monte Carlo simulation has been run."""
        return self.simulation_result is not None

    @property
    def has_critical_issues(self) -> bool:
        """Return True if any critical issues were found."""
        return len(self.issues_by_severity.get("critical", [])) > 0

    @property
    def fixed_issues_count(self) -> int:
        """Count how many issues have been fixed."""
        return sum(1 for issue in self.issues if issue.is_fixed)

    def get_issues_by_severity(self, severity: str) -> List[SecurityIssue]:
        """Get issues filtered by severity level."""
        return self.issues_by_severity.get(severity, [])

    def get_issues_by_category(self, category: str) -> List[SecurityIssue]:
        """Get issues filtered by category."""
        return self.issues_by_category.get(category, [])

    def to_dict(self) -> Dict[str, Any]:
        """Serialize report to dictionary for JSON export."""
        return {
            "report_id": self.report_id,
            "generated_at": self.generated_at.isoformat(),
            "config_file": self.config_file.to_dict(),
            "executive_summary": self.executive_summary.to_dict(),
            "issues": [issue.to_dict() for issue in self.issues],
            "fixes": [fix.to_dict() for fix in self.fixes],
            "risk_scores": {
                "initial": round(self.initial_risk_score, 2),
                "final": round(self.final_risk_score, 2),
                "reduction_percentage": round(self.risk_reduction_percentage, 2),
            },
            "simulation": self.simulation_result.to_dict() if self.simulation_result else None,
            "nist_coverage": self.nist_coverage,
            "recommendations": self.recommendations,
        }

    def __repr__(self) -> str:
        return (
            f"AnalysisReport(id={self.report_id!r}, "
            f"issues={len(self.issues)}, "
            f"risk={self.initial_risk_score:.1f}→{self.final_risk_score:.1f})"
        )
