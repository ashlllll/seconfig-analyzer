"""
Security Issue Data Model
Represents a security vulnerability detected by the Red Team analyzer.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from .risk_model import RiskProfile


# ── Constants ─────────────────────────────────────────────────────────────────

SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"]

CATEGORIES = [
    "credentials",
    "encryption",
    "access_control",
    "logging",
    "baseline",
]

NIST_FUNCTIONS = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]

STATUS_OPTIONS = ["detected", "reviewing", "fixing", "fixed", "ignored"]


# ── Security Issue ─────────────────────────────────────────────────────────────

@dataclass
class SecurityIssue:
    """
    Represents a single security vulnerability found in a configuration file.

    Created by the Red Team analyzer when a rule is matched.
    Each issue links to a RiskProfile for Monte Carlo simulation.
    """

    # ── Identity ──────────────────────────────────────────────────────────────
    issue_id: str               # e.g. "CRED-001-20260101-abc123"
    rule_id: str                # e.g. "CRED-001"
    rule_name: str

    # ── Classification ────────────────────────────────────────────────────────
    category: str               # credentials | encryption | access_control | logging | baseline
    severity: str               # critical | high | medium | low | info
    cvss_score: float           # 0.0 - 10.0

    # ── Description ───────────────────────────────────────────────────────────
    title: str
    description: str

    # ── Location in File ──────────────────────────────────────────────────────
    file_name: str
    line_number: int
    column_start: int = 0
    column_end: int = 0

    # ── Code Snippet ──────────────────────────────────────────────────────────
    vulnerable_code: str = ""
    context_before: str = ""    # lines before the vulnerable line
    context_after: str = ""     # lines after the vulnerable line

    # ── Risk Profile (for Monte Carlo) ────────────────────────────────────────
    risk_profile: Optional[RiskProfile] = None

    # ── Remediation ───────────────────────────────────────────────────────────
    remediation_hint: str = ""
    recommended_fix: str = ""
    template_id: Optional[str] = None

    # ── Framework Alignment ───────────────────────────────────────────────────
    nist_function: str = "PROTECT"      # IDENTIFY | PROTECT | DETECT | RESPOND | RECOVER
    nist_category: str = ""             # e.g. "PR.AC-1"
    cwe_id: str = ""                    # e.g. "CWE-798"
    owasp_category: Optional[str] = None

    # ── Status ────────────────────────────────────────────────────────────────
    status: str = "detected"
    confidence: float = 1.0             # 0.0 - 1.0 detection confidence

    # ── Timestamps ────────────────────────────────────────────────────────────
    detected_at: datetime = field(default_factory=datetime.now)

    # ── References ────────────────────────────────────────────────────────────
    references: List[Dict[str, str]] = field(default_factory=list)

    def __post_init__(self):
        """Validate fields after initialization."""
        assert self.severity in SEVERITY_LEVELS, \
            f"Invalid severity: {self.severity}"
        assert self.category in CATEGORIES, \
            f"Invalid category: {self.category}"
        assert self.nist_function in NIST_FUNCTIONS, \
            f"Invalid NIST function: {self.nist_function}"
        assert self.status in STATUS_OPTIONS, \
            f"Invalid status: {self.status}"
        assert 0.0 <= self.confidence <= 1.0, \
            f"Confidence must be 0-1, got {self.confidence}"

    @property
    def risk_score(self) -> float:
        """Get risk score from the associated risk profile."""
        if self.risk_profile:
            return self.risk_profile.risk_score
        return 0.0

    @property
    def severity_weight(self) -> int:
        """Numeric weight for sorting by severity."""
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return weights.get(self.severity, 0)

    @property
    def is_fixed(self) -> bool:
        """Return True if this issue has been fixed."""
        return self.status == "fixed"

    @property
    def severity_emoji(self) -> str:
        """Return emoji for severity level (used in UI)."""
        emojis = {
            "critical": "🔴",
            "high": "🟠",
            "medium": "🟡",
            "low": "🟢",
            "info": "🔵",
        }
        return emojis.get(self.severity, "⚪")

    def mark_fixed(self):
        """Mark this issue as fixed."""
        self.status = "fixed"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for reporting and export."""
        return {
            "issue_id": self.issue_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "title": self.title,
            "description": self.description,
            "file_name": self.file_name,
            "line_number": self.line_number,
            "vulnerable_code": self.vulnerable_code,
            "remediation_hint": self.remediation_hint,
            "nist_function": self.nist_function,
            "nist_category": self.nist_category,
            "cwe_id": self.cwe_id,
            "status": self.status,
            "risk_score": self.risk_score,
            "detected_at": self.detected_at.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"SecurityIssue(id={self.rule_id!r}, "
            f"severity={self.severity!r}, "
            f"line={self.line_number}, "
            f"status={self.status!r})"
        )
