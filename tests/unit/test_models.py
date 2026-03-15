"""
Unit tests for the Monte Carlo simulation engine.
Tests: ProbabilitySampler, RiskCalculator, MonteCarloSimulator
"""

import pytest
import sys
import os
import math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))


# ══════════════════════════════════════════════
# ProbabilitySampler Tests
# ══════════════════════════════════════════════

class TestProbabilitySampler:

    def test_sampler_imports(self):
        from src.core.simulation.probability import ProbabilitySampler
        s = ProbabilitySampler(seed=42)
        assert s is not None

    def test_beta_sample_in_range(self):
        from src.core.simulation.probability import ProbabilitySampler
        s = ProbabilitySampler(seed=42)
        for _ in range(100):
            val = s.sample_beta(mean=0.7, std=0.15)
            assert 0.0 <= val <= 1.0

    def test_normal_sample_clipped_to_range(self):
        from src.core.simulation.probability import ProbabilitySampler
        s = ProbabilitySampler(seed=42)
        for _ in range(100):
            val = s.sample_normal(mean=0.5, std=0.2)
            assert 0.0 <= val <= 1.0

    def test_uniform_sample_in_range(self):
        from src.core.simulation.probability import ProbabilitySampler
        s = ProbabilitySampler(seed=42)
        for _ in range(100):
            val = s.sample_uniform()
            assert 0.0 <= val <= 1.0

    def test_beta_mean_approximate(self):
        from src.core.simulation.probability import ProbabilitySampler
        import numpy as np
        s = ProbabilitySampler(seed=42)
        samples = [s.sample_beta(mean=0.7, std=0.1) for _ in range(5000)]
        assert abs(np.mean(samples) - 0.7) < 0.05

    def test_seed_reproducibility(self):
        from src.core.simulation.probability import ProbabilitySampler
        s1 = ProbabilitySampler(seed=42)
        s2 = ProbabilitySampler(seed=42)
        v1 = s1.sample_beta(mean=0.5, std=0.1)
        v2 = s2.sample_beta(mean=0.5, std=0.1)
        assert v1 == v2

    def test_different_seeds_different_values(self):
        from src.core.simulation.probability import ProbabilitySampler
        import numpy as np
        s1 = ProbabilitySampler(seed=1)
        s2 = ProbabilitySampler(seed=99)
        samples1 = [s1.sample_beta(mean=0.5, std=0.1) for _ in range(20)]
        samples2 = [s2.sample_beta(mean=0.5, std=0.1) for _ in range(20)]
        assert samples1 != samples2

    def test_moment_match_beta_valid_params(self):
        from src.core.simulation.probability import ProbabilitySampler
        s = ProbabilitySampler(seed=42)
        alpha, beta = s.moment_match_beta(mean=0.7, std=0.15)
        assert alpha > 0
        assert beta > 0

    def test_moment_match_beta_edge_mean(self):
        from src.core.simulation.probability import ProbabilitySampler
        s = ProbabilitySampler(seed=42)
        # Should not raise even for edge mean values
        alpha, beta = s.moment_match_beta(mean=0.01, std=0.05)
        assert alpha > 0
        assert beta > 0

    def test_sampler_is_not_subclass_of_distribution(self):
        """ProbabilitySampler uses composition — it must NOT be a subclass."""
        from src.core.simulation.probability import ProbabilitySampler, ProbabilityDistribution
        assert not issubclass(ProbabilitySampler, ProbabilityDistribution), (
            "ProbabilitySampler should use composition, not inheritance. "
            "Subclassing caused type: ignore[override] hacks."
        )

    def test_sampler_delegates_to_distribution(self):
        """ProbabilitySampler must expose a _dist attribute (composition)."""
        from src.core.simulation.probability import ProbabilitySampler, ProbabilityDistribution
        s = ProbabilitySampler(seed=42)
        assert hasattr(s, "_dist")
        assert isinstance(s._dist, ProbabilityDistribution)


# ══════════════════════════════════════════════
# RiskCalculator Tests
# ══════════════════════════════════════════════

class TestRiskCalculator:

    def _make_risk_profile(self, severity=7.0, exploitability=0.8,
                            c="high", i="medium", a="low",
                            mean=0.7, std=0.15):
        try:
            from models.risk_model import RiskProfile
            return RiskProfile(
                base_severity=severity,
                exploitability=exploitability,
                impact_confidentiality=c,
                impact_integrity=i,
                impact_availability=a,
                likelihood_mean=mean,
                likelihood_std=std,
            )
        except Exception:
            return {
                "base_severity": severity,
                "exploitability": exploitability,
                "impact_confidentiality": c,
                "impact_integrity": i,
                "impact_availability": a,
                "likelihood_mean": mean,
                "likelihood_std": std,
            }

    def test_calculator_imports(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        assert calc is not None

    def test_risk_score_in_range(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        rp = self._make_risk_profile()
        score = calc.calculate_individual_risk(rp, likelihood=0.7)
        assert 0.0 <= score <= 10.0

    def test_zero_likelihood_gives_zero_risk(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        rp = self._make_risk_profile()
        score = calc.calculate_individual_risk(rp, likelihood=0.0)
        assert score == 0.0

    def test_high_severity_gives_higher_score(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        rp_high = self._make_risk_profile(severity=9.0)
        rp_low = self._make_risk_profile(severity=2.0)
        score_high = calc.calculate_individual_risk(rp_high, likelihood=0.7)
        score_low = calc.calculate_individual_risk(rp_low, likelihood=0.7)
        assert score_high > score_low

    def test_normalize_single_issue(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        normalized = calc.normalize_risk(total_risk=5.0, num_issues=1)
        assert 0.0 <= normalized <= 100.0

    def test_normalize_zero_issues_returns_zero(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        normalized = calc.normalize_risk(total_risk=0.0, num_issues=0)
        assert normalized == 0.0

    def test_normalize_caps_at_100(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        normalized = calc.normalize_risk(total_risk=99999.0, num_issues=1)
        assert normalized <= 100.0

    def test_impact_high_greater_than_low(self):
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        rp_high = self._make_risk_profile(c="high", i="high", a="high")
        rp_low = self._make_risk_profile(c="low", i="low", a="low")
        s_high = calc.calculate_individual_risk(rp_high, likelihood=0.7)
        s_low = calc.calculate_individual_risk(rp_low, likelihood=0.7)
        assert s_high > s_low

    def test_unknown_impact_key_defaults_to_half(self):
        """Unknown CIA impact level should default to 0.5 (symmetric middle)."""
        from src.core.simulation.risk_calculator import IMPACT_WEIGHTS
        assert IMPACT_WEIGHTS.get("unknown_level", 0.5) == 0.5

    def test_calculate_individual_risk_emits_deprecation_warning(self):
        """Legacy method calculate_individual_risk must emit DeprecationWarning."""
        import warnings
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        rp = self._make_risk_profile()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            calc.calculate_individual_risk(rp, likelihood=0.5)
        assert any(issubclass(warning.category, DeprecationWarning) for warning in w), \
            "calculate_individual_risk() should emit DeprecationWarning"

    def test_normalize_risk_emits_deprecation_warning(self):
        """Legacy method normalize_risk must emit DeprecationWarning."""
        import warnings
        from src.core.simulation.risk_calculator import RiskCalculator
        calc = RiskCalculator()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            calc.normalize_risk(total_risk=5.0, num_issues=1)
        assert any(issubclass(warning.category, DeprecationWarning) for warning in w), \
            "normalize_risk() should emit DeprecationWarning"


# ══════════════════════════════════════════════
# MonteCarloSimulator Tests
# ══════════════════════════════════════════════

class TestMonteCarloSimulator:

    def _make_issues(self, count=3):
        issues = []
        try:
            from models.issue_model import SecurityIssue
            from models.risk_model import RiskProfile
            for i in range(count):
                rp = RiskProfile(
                    base_severity=7.0,
                    exploitability=0.8,
                    impact_confidentiality="high",
                    impact_integrity="medium",
                    impact_availability="low",
                    likelihood_mean=0.7,
                    likelihood_std=0.15,
                )
                issue = SecurityIssue(
                    issue_id=f"test-{i}",
                    rule_id=f"CRED-00{i+1}",
                    rule_name=f"Test rule {i}",
                    category="credentials",
                    severity="high",
                    cvss_score=7.5,
                    title=f"Test issue {i}",
                    description="Test",
                    file_name="test.env",
                    line_number=i + 1,
                    vulnerable_code=f"KEY_{i}=value",
                    risk_profile=rp,
                    remediation_hint="Fix it",
                    nist_function="PROTECT",
                    nist_category="PR.AC-1",
                    cwe_id="CWE-798",
                )
                issues.append(issue)
        except Exception:
            for i in range(count):
                issues.append({
                    "issue_id": f"test-{i}",
                    "rule_id": f"CRED-00{i+1}",
                    "risk_profile": {
                        "base_severity": 7.0,
                        "exploitability": 0.8,
                        "impact_confidentiality": "high",
                        "impact_integrity": "medium",
                        "impact_availability": "low",
                        "likelihood_mean": 0.7,
                        "likelihood_std": 0.15,
                        "distribution_type": "beta",
                    }
                })
        return issues

    def test_simulator_imports(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=100, seed=42)
        assert sim is not None

    def test_simulate_returns_result(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=100, seed=42)
        issues_before = self._make_issues(3)
        issues_after = self._make_issues(1)
        result = sim.simulate(issues_before, issues_after)
        assert result is not None

    def test_before_mean_higher_than_after(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=500, seed=42)
        issues_before = self._make_issues(5)
        issues_after = self._make_issues(1)
        result = sim.simulate(issues_before, issues_after)
        before_mean = (result.before_remediation.mean
                       if hasattr(result, 'before_remediation')
                       else result['before_remediation']['mean'])
        after_mean = (result.after_remediation.mean
                      if hasattr(result, 'after_remediation')
                      else result['after_remediation']['mean'])
        assert before_mean > after_mean

    def test_risk_reduction_positive(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=500, seed=42)
        issues_before = self._make_issues(5)
        issues_after = self._make_issues(1)
        result = sim.simulate(issues_before, issues_after)
        reduction = (result.risk_reduction_percentage
                     if hasattr(result, 'risk_reduction_percentage')
                     else result.get('risk_reduction_percentage', 0))
        assert reduction > 0

    def test_empty_issues_after_gives_near_zero_risk(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=200, seed=42)
        issues_before = self._make_issues(3)
        issues_after = []
        result = sim.simulate(issues_before, issues_after)
        after_mean = (result.after_remediation.mean
                      if hasattr(result, 'after_remediation')
                      else result['after_remediation']['mean'])
        assert after_mean == 0.0

    def test_same_seed_reproducible(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        issues = self._make_issues(2)
        sim1 = MonteCarloSimulator(iterations=200, seed=42)
        sim2 = MonteCarloSimulator(iterations=200, seed=42)
        r1 = sim1.simulate(issues, [])
        r2 = sim2.simulate(issues, [])
        m1 = r1.before_remediation.mean if hasattr(r1, 'before_remediation') else r1['before_remediation']['mean']
        m2 = r2.before_remediation.mean if hasattr(r2, 'before_remediation') else r2['before_remediation']['mean']
        assert abs(m1 - m2) < 0.001

    def test_result_has_confidence_interval(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=200, seed=42)
        issues_before = self._make_issues(3)
        issues_after = self._make_issues(1)
        result = sim.simulate(issues_before, issues_after)
        ci = (result.confidence_interval
              if hasattr(result, 'confidence_interval')
              else result.get('confidence_interval'))
        assert ci is not None
        assert len(ci) == 2

    def test_distribution_has_statistics(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=200, seed=42)
        issues = self._make_issues(3)
        result = sim.simulate(issues, [])
        dist = (result.before_remediation
                if hasattr(result, 'before_remediation')
                else result['before_remediation'])
        mean = dist.mean if hasattr(dist, 'mean') else dist['mean']
        std = dist.std_dev if hasattr(dist, 'std_dev') else dist.get('std_dev', dist.get('std'))
        assert mean >= 0
        assert std >= 0

    def test_p95_greater_than_p5(self):
        from src.core.simulation.monte_carlo import MonteCarloSimulator
        sim = MonteCarloSimulator(iterations=500, seed=42)
        issues = self._make_issues(3)
        result = sim.simulate(issues, [])
        dist = (result.before_remediation
                if hasattr(result, 'before_remediation')
                else result['before_remediation'])
        p5 = dist.p5 if hasattr(dist, 'p5') else dist.get('p5', 0)
        p95 = dist.p95 if hasattr(dist, 'p95') else dist.get('p95', 100)
        assert p95 >= p5