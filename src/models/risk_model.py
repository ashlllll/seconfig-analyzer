"""
Risk Model
Defines risk profiles used by the Monte Carlo simulation engine.
"""
from dataclasses import dataclass, field
from typing import List, Tuple


# ── Constants ─────────────────────────────────────────────────────────────────

IMPACT_WEIGHTS = {
    "high":   1.0,
    "medium": 0.6,
    "low":    0.3,
    "none":   0.0,
}

SEVERITY_CVSS_RANGES = {
    "critical": (9.0, 10.0),
    "high":     (7.0, 8.9),
    "medium":   (4.0, 6.9),
    "low":      (0.1, 3.9),
    "info":     (0.0, 0.0),
}


# ── Risk Profile ──────────────────────────────────────────────────────────────

@dataclass
class RiskProfile:
    """
    Risk profile for a single security issue.
    Used as input parameters for the Monte Carlo simulation.

    Each issue has a probability distribution for its likelihood,
    allowing the simulator to sample across many iterations.
    """

    # ── Base Scores ───────────────────────────────────────────────────────────
    base_severity: float        # 0.0 - 10.0 (CVSS-style)
    exploitability: float       # 0.0 - 1.0

    # ── CIA Impact ────────────────────────────────────────────────────────────
    impact_confidentiality: str     # 'high' | 'medium' | 'low' | 'none'
    impact_integrity: str
    impact_availability: str

    # ── Probability Distribution (for Monte Carlo) ────────────────────────────
    likelihood_mean: float          # 0.0 - 1.0
    likelihood_std: float           # standard deviation
    distribution_type: str = 'beta' # 'beta' | 'normal' | 'uniform'

    # ── Computed Score (set after calculation) ────────────────────────────────
    risk_score: float = 0.0         # 0.0 - 100.0

    def __post_init__(self):
        """Validate and compute risk score on creation."""
        self._validate()
        self.risk_score = self.calculate_risk_score()

    def _validate(self):
        """Validate input ranges."""
        assert 0.0 <= self.base_severity <= 10.0, \
            f"base_severity must be 0-10, got {self.base_severity}"
        assert 0.0 <= self.exploitability <= 1.0, \
            f"exploitability must be 0-1, got {self.exploitability}"
        assert 0.0 <= self.likelihood_mean <= 1.0, \
            f"likelihood_mean must be 0-1, got {self.likelihood_mean}"
        assert self.impact_confidentiality in IMPACT_WEIGHTS, \
            f"Invalid impact_confidentiality: {self.impact_confidentiality}"
        assert self.impact_integrity in IMPACT_WEIGHTS, \
            f"Invalid impact_integrity: {self.impact_integrity}"
        assert self.impact_availability in IMPACT_WEIGHTS, \
            f"Invalid impact_availability: {self.impact_availability}"

    def calculate_risk_score(self) -> float:
        """
        Calculate deterministic risk score.

        Formula:
            risk = base_severity × exploitability × impact_factor × likelihood_mean
            normalized to 0-100
        """
        c = IMPACT_WEIGHTS[self.impact_confidentiality]
        i = IMPACT_WEIGHTS[self.impact_integrity]
        a = IMPACT_WEIGHTS[self.impact_availability]
        impact_factor = (c + i + a) / 3.0

        raw = (
            self.base_severity *
            self.exploitability *
            impact_factor *
            self.likelihood_mean
        )

        # Normalize: max possible = 10 * 1 * 1 * 1 = 10 → scale to 100
        return round(min(raw * 10.0, 100.0), 2)

    @property
    def impact_factor(self) -> float:
        """Average CIA impact factor."""
        c = IMPACT_WEIGHTS[self.impact_confidentiality]
        i = IMPACT_WEIGHTS[self.impact_integrity]
        a = IMPACT_WEIGHTS[self.impact_availability]
        return round((c + i + a) / 3.0, 3)

    @property
    def priority(self) -> str:
        """Determine fix priority based on risk score."""
        if self.risk_score >= 70:
            return "immediate"
        elif self.risk_score >= 40:
            return "high"
        elif self.risk_score >= 20:
            return "medium"
        else:
            return "low"

    def to_dict(self) -> dict:
        """Serialize to dictionary."""
        return {
            "base_severity": self.base_severity,
            "exploitability": self.exploitability,
            "impact_confidentiality": self.impact_confidentiality,
            "impact_integrity": self.impact_integrity,
            "impact_availability": self.impact_availability,
            "likelihood_mean": self.likelihood_mean,
            "likelihood_std": self.likelihood_std,
            "distribution_type": self.distribution_type,
            "risk_score": self.risk_score,
            "impact_factor": self.impact_factor,
            "priority": self.priority,
        }


# ── Simulation Result Models ───────────────────────────────────────────────────

@dataclass
class RiskDistribution:
    """Statistical summary of a Monte Carlo risk distribution."""

    mean: float
    median: float
    std_dev: float

    # Percentiles
    p5: float
    p25: float
    p75: float
    p95: float

    # Raw data for visualization
    distribution: List[float] = field(default_factory=list)
    histogram_bins: List[float] = field(default_factory=list)
    histogram_counts: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "mean": round(self.mean, 2),
            "median": round(self.median, 2),
            "std_dev": round(self.std_dev, 2),
            "p5": round(self.p5, 2),
            "p25": round(self.p25, 2),
            "p75": round(self.p75, 2),
            "p95": round(self.p95, 2),
        }


@dataclass
class SimulationResult:
    """Full result of a Monte Carlo simulation run."""

    # Simulation parameters
    iterations: int
    seed: int

    # Risk distributions
    before_remediation: RiskDistribution
    after_remediation: RiskDistribution

    # Improvement metrics
    risk_reduction: float               # absolute reduction
    risk_reduction_percentage: float    # percentage reduction

    # Statistical significance
    confidence_level: float = 0.95
    confidence_interval: Tuple[float, float] = (0.0, 0.0)
    is_significant: bool = False
    p_value: float = 1.0

    def to_dict(self) -> dict:
        return {
            "iterations": self.iterations,
            "seed": self.seed,
            "before": self.before_remediation.to_dict(),
            "after": self.after_remediation.to_dict(),
            "risk_reduction": round(self.risk_reduction, 2),
            "risk_reduction_percentage": round(self.risk_reduction_percentage, 2),
            "confidence_level": self.confidence_level,
            "confidence_interval": list(self.confidence_interval),
            "is_significant": self.is_significant,
            "p_value": round(self.p_value, 4),
        }
