"""
Monte Carlo Simulator
Runs probabilistic risk simulation to quantify and compare
security risk before and after remediation.
"""
import numpy as np
from typing import List, Tuple

from .probability import ProbabilityDistribution
from .risk_calculator import RiskCalculator
from ...models.issue_model import SecurityIssue
from ...models.risk_model import RiskDistribution, SimulationResult


class MonteCarloSimulator:
    """
    Runs Monte Carlo simulation to produce risk distributions.

    For each iteration:
        1. Sample likelihood for each issue from its probability distribution
        2. Compute aggregate risk score for that iteration
    After N iterations:
        3. Produce a distribution of risk scores
        4. Calculate statistics (mean, median, percentiles)
        5. Compare before vs after remediation

    The simulation is reproducible: same seed → same results.
    """

    def __init__(self, iterations: int = 10000, seed: int = 42):
        """
        Initialize the simulator.

        Args:
            iterations: Number of Monte Carlo iterations (default 10,000)
            seed:       Random seed for reproducibility (default 42)
        """
        self.iterations = iterations
        self.seed = seed
        self.probability = ProbabilityDistribution(seed=seed)
        self.calculator = RiskCalculator()

    def simulate(
        self,
        issues_before: List[SecurityIssue],
        issues_after: List[SecurityIssue],
        confidence_level: float = 0.95,
    ) -> SimulationResult:
        """
        Run Monte Carlo simulation comparing before and after remediation.

        Args:
            issues_before: Issues detected before any fixes applied
            issues_after:  Issues remaining after fixes applied
            confidence_level: Confidence level for interval estimation (0-1)

        Returns:
            SimulationResult with full statistical comparison
        """
        confidence_level = float(np.clip(confidence_level, 0.5, 0.999))

        # Run simulation for both scenarios
        dist_before = self._run_simulation(issues_before)
        dist_after = self._run_simulation(issues_after)

        # Compute statistics
        stats_before = self._compute_statistics(dist_before)
        stats_after = self._compute_statistics(dist_after)

        # Compute improvement metrics
        risk_reduction = float(stats_before.mean - stats_after.mean)
        risk_reduction_pct = self.calculator.calculate_risk_reduction(
            stats_before.mean, stats_after.mean
        )

        # Confidence interval for the risk reduction
        ci = self._confidence_interval(
            dist_before,
            dist_after,
            confidence=confidence_level,
        )

        # Statistical significance test
        is_significant, p_value = self._significance_test(dist_before, dist_after)

        return SimulationResult(
            iterations=self.iterations,
            seed=self.seed,
            before_remediation=stats_before,
            after_remediation=stats_after,
            risk_reduction=round(risk_reduction, 2),
            risk_reduction_percentage=risk_reduction_pct,
            confidence_level=confidence_level,
            confidence_interval=ci,
            is_significant=is_significant,
            p_value=p_value,
        )

    def _run_simulation(self, issues: List[SecurityIssue]) -> np.ndarray:
        """
        Run N iterations for a given set of issues.

        For each iteration:
            - Sample a likelihood value for each issue
            - Compute the total risk score

        Args:
            issues: List of SecurityIssue objects

        Returns:
            Array of shape (iterations,) containing risk scores
        """
        if not issues:
            return np.zeros(self.iterations)

        # Pre-sample all likelihoods: shape (iterations, num_issues)
        num_issues = len(issues)
        all_likelihoods = np.zeros((self.iterations, num_issues))

        for i, issue in enumerate(issues):
            rp = issue.risk_profile
            if rp is None:
                all_likelihoods[:, i] = 0.5
                continue

            samples = self.probability.sample(
                distribution_type=rp.distribution_type,
                mean=rp.likelihood_mean,
                std=rp.likelihood_std,
                size=self.iterations,
            )
            all_likelihoods[:, i] = samples

        # Compute risk for each iteration using vectorized operations
        risk_scores = np.zeros(self.iterations)

        for i, issue in enumerate(issues):
            rp = issue.risk_profile
            if rp is None:
                continue

            # Compute individual risk for all iterations at once
            from .risk_calculator import IMPACT_WEIGHTS
            c = IMPACT_WEIGHTS.get(rp.impact_confidentiality, 0.5)
            ia = IMPACT_WEIGHTS.get(rp.impact_integrity, 0.5)
            a = IMPACT_WEIGHTS.get(rp.impact_availability, 0.3)
            impact_factor = (c + ia + a) / 3.0

            individual_risks = (
                rp.base_severity *
                rp.exploitability *
                impact_factor *
                all_likelihoods[:, i]
            )
            risk_scores += individual_risks

        # Normalize to 0-100 with sub-linear issue scaling so scores don't
        # collapse to 100 when many issues exist, while still reflecting
        # higher aggregate risk for larger issue sets.
        scale_denominator = max(10.0, 10.0 * (num_issues ** 0.75))
        risk_scores = np.clip((risk_scores / scale_denominator) * 100.0, 0.0, 100.0)

        return risk_scores

    def _compute_statistics(self, distribution: np.ndarray) -> RiskDistribution:
        """
        Compute descriptive statistics from a risk distribution.

        Args:
            distribution: Array of risk score samples

        Returns:
            RiskDistribution with mean, median, std, percentiles
        """
        # Compute histogram for visualization
        counts, bin_edges = np.histogram(distribution, bins=50)

        return RiskDistribution(
            mean=float(np.mean(distribution)),
            median=float(np.median(distribution)),
            std_dev=float(np.std(distribution)),
            p5=float(np.percentile(distribution, 5)),
            p25=float(np.percentile(distribution, 25)),
            p75=float(np.percentile(distribution, 75)),
            p95=float(np.percentile(distribution, 95)),
            distribution=distribution.tolist(),
            histogram_bins=bin_edges.tolist(),
            histogram_counts=counts.tolist(),
        )

    def _confidence_interval(
        self,
        dist_before: np.ndarray,
        dist_after: np.ndarray,
        confidence: float = 0.95,
    ) -> Tuple[float, float]:
        """
        Compute confidence interval for the risk reduction.

        Args:
            dist_before: Risk distribution before remediation
            dist_after:  Risk distribution after remediation
            confidence:  Confidence level (default 0.95 = 95%)

        Returns:
            (lower_bound, upper_bound) of the confidence interval
        """
        diff = dist_before - dist_after
        alpha = 1.0 - confidence
        lower = float(np.percentile(diff, (alpha / 2) * 100))
        upper = float(np.percentile(diff, (1 - alpha / 2) * 100))
        return round(lower, 2), round(upper, 2)

    def _significance_test(
        self,
        dist_before: np.ndarray,
        dist_after: np.ndarray,
    ) -> Tuple[bool, float]:
        """
        Test if the risk reduction is statistically significant.

        Uses the Wilcoxon signed-rank test (non-parametric).
        Null hypothesis: no difference between before and after.

        Args:
            dist_before: Risk distribution before remediation
            dist_after:  Risk distribution after remediation

        Returns:
            (is_significant, p_value)
        """
        if np.allclose(dist_before, dist_after):
            # No measurable difference between distributions.
            return False, 1.0

        try:
            from scipy.stats import wilcoxon

            # Use a sample to keep computation fast (max 1000 pairs)
            sample_size = min(1000, self.iterations)
            rng = np.random.default_rng(self.seed)
            idx = rng.choice(self.iterations, sample_size, replace=False)

            statistic, p_value = wilcoxon(
                dist_before[idx],
                dist_after[idx],
                alternative="greater",
            )
            if np.isnan(p_value):
                return False, 1.0
            is_significant = bool(p_value < 0.05)
            return is_significant, round(float(p_value), 4)

        except Exception:
            # If scipy not available or test fails, return non-significant
            return False, 1.0
