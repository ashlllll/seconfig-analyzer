"""
Simulation Service
Runs Monte Carlo risk simulation and computes risk scores.
"""
from typing import List

from ..core.simulation.monte_carlo import MonteCarloSimulator
from ..core.simulation.risk_calculator import RiskCalculator
from ..models.issue_model import SecurityIssue
from ..models.risk_model import SimulationResult


class SimulationService:
    """
    Orchestrates Monte Carlo risk simulation.

    Computes:
        - Deterministic initial risk score
        - Probabilistic risk distribution (before remediation)
        - Probabilistic risk distribution (after remediation)
        - Statistical comparison and significance test
    """

    def __init__(self, iterations: int = 10000, seed: int = 42):
        """
        Initialize the simulation service.

        Args:
            iterations: Number of Monte Carlo iterations
            seed:       Random seed for reproducibility
        """
        self.iterations = iterations
        self.seed = seed
        self.simulator = MonteCarloSimulator(iterations=iterations, seed=seed)
        self.calculator = RiskCalculator()

    def calculate_initial_risk(self, issues: List[SecurityIssue]) -> float:
        """
        Compute a deterministic risk score (uses mean likelihoods).

        Args:
            issues: List of SecurityIssue objects

        Returns:
            Risk score in [0, 100]
        """
        return self.calculator.calculate_total_risk(issues)

    def run_monte_carlo(
        self,
        issues_before: List[SecurityIssue],
        issues_after: List[SecurityIssue],
    ) -> SimulationResult:
        """
        Run full Monte Carlo simulation comparing before and after.

        Args:
            issues_before: Issues before remediation
            issues_after:  Issues remaining after remediation

        Returns:
            SimulationResult with full statistics
        """
        return self.simulator.simulate(issues_before, issues_after)

    def calculate_risk_reduction(
        self,
        risk_before: float,
        risk_after: float,
    ) -> float:
        """
        Calculate percentage risk reduction.

        Args:
            risk_before: Initial risk score
            risk_after:  Post-remediation risk score

        Returns:
            Percentage reduction (0-100)
        """
        return self.calculator.calculate_risk_reduction(risk_before, risk_after)
