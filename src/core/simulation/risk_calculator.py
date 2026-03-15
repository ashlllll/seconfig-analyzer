"""
Risk Calculator
Computes deterministic and probabilistic risk scores for security issues.
"""
import warnings
import numpy as np
from typing import List, Optional

from ...models.issue_model import SecurityIssue
from ...models.risk_model import RiskProfile


# CIA impact weights — all three dimensions use the same default (0.5)
# so that unknown values produce a symmetric, moderate impact estimate.
IMPACT_WEIGHTS = {
    "high":   1.0,
    "medium": 0.6,
    "low":    0.3,
    "none":   0.0,
}


class RiskCalculator:
    """
    Calculates risk scores for individual issues and aggregates.

    Two modes:
        1. Deterministic — uses the mean likelihood value
        2. Probabilistic  — uses a sampled likelihood (for Monte Carlo)
    """

    def calculate_issue_risk(
        self,
        issue: SecurityIssue,
        likelihood_override: Optional[float] = None,
    ) -> float:
        """
        Calculate risk score for a single issue.

        Formula:
            risk = base_severity × exploitability × impact_factor × likelihood
            (raw value, not yet normalised to 0-100)

        Args:
            issue:               SecurityIssue object
            likelihood_override: If provided, use this likelihood instead
                                 of the profile mean (used in Monte Carlo)

        Returns:
            Raw risk value (pass to _normalize for a 0-100 score)
        """
        rp = issue.risk_profile
        if rp is None:
            return 0.0

        likelihood = (
            likelihood_override if likelihood_override is not None
            else rp.likelihood_mean
        )
        return self._compute_risk(rp, likelihood)

    def calculate_total_risk(
        self,
        issues: List[SecurityIssue],
        likelihood_overrides: Optional[List[float]] = None,
    ) -> float:
        """
        Calculate the aggregate risk score for a list of issues.

        Args:
            issues:               List of SecurityIssue objects
            likelihood_overrides: Optional per-issue likelihood values

        Returns:
            Normalised total risk score in [0, 100]
        """
        if not issues:
            return 0.0

        total = 0.0
        for idx, issue in enumerate(issues):
            override = None
            if likelihood_overrides and idx < len(likelihood_overrides):
                override = likelihood_overrides[idx]
            total += self.calculate_issue_risk(issue, override)

        return self._normalize(total, len(issues))

    def calculate_risk_reduction(
        self,
        risk_before: float,
        risk_after: float,
    ) -> float:
        """
        Calculate percentage risk reduction.

        Args:
            risk_before: Risk score before remediation
            risk_after:  Risk score after remediation

        Returns:
            Percentage reduction (0-100)
        """
        if risk_before <= 0:
            return 0.0
        reduction = ((risk_before - risk_after) / risk_before) * 100.0
        return round(max(0.0, min(100.0, reduction)), 2)

    # ── Legacy compatibility methods ──────────────────────────────────────────
    # Kept for backward compatibility with older tests. Use the canonical
    # methods above in all new code.

    def calculate_individual_risk(
        self,
        risk_profile: RiskProfile,
        likelihood: Optional[float] = None,
    ) -> float:
        """
        .. deprecated::
            Use :meth:`calculate_issue_risk` instead.
        """
        warnings.warn(
            "calculate_individual_risk() is deprecated; "
            "use calculate_issue_risk() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        likelihood_value = (
            risk_profile.likelihood_mean if likelihood is None else likelihood
        )
        return self._compute_risk(risk_profile, likelihood_value)

    def normalize_risk(self, total_risk: float, num_issues: int) -> float:
        """
        .. deprecated::
            Use :meth:`_normalize` directly or ``calculate_total_risk`` instead.
        """
        warnings.warn(
            "normalize_risk() is deprecated; use _normalize() instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._normalize(total_risk, num_issues)

    # ── Core computation ──────────────────────────────────────────────────────

    def _compute_risk(self, rp: RiskProfile, likelihood: float) -> float:
        """
        Core risk computation formula.

        Args:
            rp:         RiskProfile containing severity, exploitability, impact
            likelihood: Sampled or mean likelihood value (0-1)

        Returns:
            Raw risk value (before normalisation)
        """
        conf  = IMPACT_WEIGHTS.get(rp.impact_confidentiality, 0.5)
        integ = IMPACT_WEIGHTS.get(rp.impact_integrity, 0.5)
        avail = IMPACT_WEIGHTS.get(rp.impact_availability, 0.5)
        impact_factor = (conf + integ + avail) / 3.0

        return (
            rp.base_severity
            * rp.exploitability
            * impact_factor
            * float(np.clip(likelihood, 0.0, 1.0))
        )

    def _normalize(self, total_raw: float, num_issues: int) -> float:
        """
        Normalise total raw risk to a 0-100 scale.

        Max possible raw risk per issue = 10 (severity) × 1 (exploit)
        × 1 (impact) × 1 (likelihood) = 10.

        Args:
            total_raw:  Sum of raw risk scores
            num_issues: Number of issues

        Returns:
            Normalised score in [0, 100]
        """
        if num_issues == 0:
            return 0.0

        max_possible = num_issues * 10.0
        normalised = (total_raw / max_possible) * 100.0
        return round(float(np.clip(normalised, 0.0, 100.0)), 2)