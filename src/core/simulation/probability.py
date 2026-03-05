"""
Probability Distributions
Handles sampling from different probability distributions
used in the Monte Carlo simulation.
"""
import numpy as np
from typing import Tuple


class ProbabilityDistribution:
    """
    Provides sampling methods for different probability distributions.

    Supported distributions:
        - Beta    : Best for likelihood values bounded in [0, 1]
        - Normal  : For moderate uncertainty, clipped to [0, 1]
        - Uniform : For complete uncertainty
    """

    def __init__(self, seed: int = 42):
        """
        Initialize with a fixed seed for reproducibility.

        Args:
            seed: Random seed (default 42 for reproducibility)
        """
        self.rng = np.random.default_rng(seed)

    def sample(
        self,
        distribution_type: str,
        mean: float,
        std: float,
        size: int = 1,
    ) -> np.ndarray:
        """
        Sample from the specified distribution.

        Args:
            distribution_type: 'beta' | 'normal' | 'uniform'
            mean:  Mean of the distribution (0-1)
            std:   Standard deviation
            size:  Number of samples

        Returns:
            NumPy array of sampled values in [0, 1]
        """
        if distribution_type == "beta":
            return self.sample_beta(mean, std, size)
        elif distribution_type == "normal":
            return self.sample_normal(mean, std, size)
        elif distribution_type == "uniform":
            return self.sample_uniform(size)
        else:
            # Default to beta
            return self.sample_beta(mean, std, size)

    def sample_beta(
        self,
        mean: float,
        std: float,
        size: int,
    ) -> np.ndarray:
        """
        Sample from a Beta distribution.

        Beta is ideal for probabilities: it is bounded in [0, 1]
        and can represent a wide range of shapes.

        Alpha and beta parameters are derived using moment matching:
            alpha = mean * ((mean * (1 - mean) / var) - 1)
            beta  = (1 - mean) * ((mean * (1 - mean) / var) - 1)

        Args:
            mean: Mean likelihood (0-1)
            std:  Standard deviation
            size: Number of samples

        Returns:
            Array of samples in [0, 1]
        """
        # Clamp mean to valid range
        mean = float(np.clip(mean, 0.01, 0.99))
        std = max(float(std), 0.01)

        var = std ** 2

        # Moment matching to get alpha and beta
        common = (mean * (1.0 - mean) / var) - 1.0

        if common <= 0:
            # Variance too large — fall back to uniform-like beta
            alpha, beta_param = 1.0, 1.0
        else:
            alpha = mean * common
            beta_param = (1.0 - mean) * common

        alpha = max(0.1, alpha)
        beta_param = max(0.1, beta_param)

        return self.rng.beta(alpha, beta_param, size=size)

    def sample_normal(
        self,
        mean: float,
        std: float,
        size: int,
    ) -> np.ndarray:
        """
        Sample from a Normal distribution, clipped to [0, 1].

        Args:
            mean: Mean (0-1)
            std:  Standard deviation
            size: Number of samples

        Returns:
            Array of samples clipped to [0, 1]
        """
        samples = self.rng.normal(loc=mean, scale=std, size=size)
        return np.clip(samples, 0.0, 1.0)

    def sample_uniform(self, size: int) -> np.ndarray:
        """
        Sample from a Uniform distribution over [0, 1].

        Used when likelihood is completely unknown.

        Args:
            size: Number of samples

        Returns:
            Array of uniformly distributed samples in [0, 1]
        """
        return self.rng.uniform(0.0, 1.0, size=size)

    def moment_match_beta(
        self,
        mean: float,
        std: float,
    ) -> Tuple[float, float]:
        """
        Calculate Beta distribution parameters from mean and std.

        Args:
            mean: Target mean (0-1)
            std:  Target standard deviation

        Returns:
            (alpha, beta) parameters
        """
        mean = float(np.clip(mean, 0.01, 0.99))
        std = max(float(std), 0.01)
        var = std ** 2

        common = (mean * (1.0 - mean) / var) - 1.0
        common = max(common, 0.1)

        alpha = max(0.1, mean * common)
        beta = max(0.1, (1.0 - mean) * common)

        return alpha, beta
