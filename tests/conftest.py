"""
tests/conftest.py
~~~~~~~~~~~~~~~~~
Pytest configuration and shared fixtures for SecConfig Analyzer tests.

Adds src/ to sys.path so imports work from any test file without
needing to install the package.
"""
import os
import sys
import pytest

# ── sys.path setup ────────────────────────────────────────────────────────────
# Ensure both project root and src/ are on the path so tests can do:
#   from src.parsers.env_parser import EnvParser
#   from src.parsers.env_parser import EnvParser   (either works)

_HERE    = os.path.dirname(os.path.abspath(__file__))
_ROOT    = os.path.dirname(_HERE)
_SRC     = os.path.join(_ROOT, "src")

for _p in [_ROOT, _SRC]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ── Shared path fixtures ──────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def project_root() -> str:
    """Return the absolute path to the project root directory."""
    return _ROOT


@pytest.fixture(scope="session")
def src_dir() -> str:
    """Return the absolute path to src/."""
    return _SRC


@pytest.fixture(scope="session")
def rules_dir() -> str:
    """Return the absolute path to data/rules_catalog/."""
    return os.path.join(_ROOT, "data", "rules_catalog")


@pytest.fixture(scope="session")
def templates_dir() -> str:
    """Return the absolute path to data/templates_catalog/."""
    return os.path.join(_ROOT, "data", "templates_catalog")


@pytest.fixture(scope="session")
def synthetic_data_dir() -> str:
    """Return the absolute path to data/synthetic_configs/."""
    return os.path.join(_ROOT, "data", "synthetic_configs")


@pytest.fixture(scope="session")
def vulnerable_dir(synthetic_data_dir) -> str:
    """Return the path to data/synthetic_configs/vulnerable/."""
    return os.path.join(synthetic_data_dir, "vulnerable")


@pytest.fixture(scope="session")
def secure_dir(synthetic_data_dir) -> str:
    """Return the path to data/synthetic_configs/secure/."""
    return os.path.join(synthetic_data_dir, "secure")


@pytest.fixture(scope="session")
def edge_cases_dir(synthetic_data_dir) -> str:
    """Return the path to data/synthetic_configs/edge_cases/."""
    return os.path.join(synthetic_data_dir, "edge_cases")


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


# ── Shared content fixtures ───────────────────────────────────────────────────

@pytest.fixture(scope="session")
def vulnerable_env_content(vulnerable_dir) -> str:
    return _read_text(os.path.join(vulnerable_dir, "sample_01.env"))


@pytest.fixture(scope="session")
def secure_env_content(secure_dir) -> str:
    return _read_text(os.path.join(secure_dir, "best_practice_01.env"))


@pytest.fixture(scope="session")
def vulnerable_yaml_content(vulnerable_dir) -> str:
    return _read_text(os.path.join(vulnerable_dir, "sample_03.yaml"))


@pytest.fixture(scope="session")
def vulnerable_json_content(vulnerable_dir) -> str:
    return _read_text(os.path.join(vulnerable_dir, "sample_04.json"))


@pytest.fixture(scope="session")
def empty_content(edge_cases_dir) -> str:
    return _read_text(os.path.join(edge_cases_dir, "empty.env"))


@pytest.fixture(scope="session")
def comments_only_content(edge_cases_dir) -> str:
    return _read_text(os.path.join(edge_cases_dir, "comments_only.env"))


@pytest.fixture(scope="session")
def malformed_yaml_content(edge_cases_dir) -> str:
    return _read_text(os.path.join(edge_cases_dir, "malformed.yaml"))


# ── Parser fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def env_parser():
    """Return an EnvParser instance."""
    from src.parsers.env_parser import EnvParser
    return EnvParser()


@pytest.fixture(scope="session")
def yaml_parser():
    """Return a YamlParser instance."""
    from src.parsers.yaml_parser import YamlParser
    return YamlParser()


@pytest.fixture(scope="session")
def json_parser():
    """Return a JsonParser instance."""
    from src.parsers.json_parser import JsonParser
    return JsonParser()


# ── Simple config factories ───────────────────────────────────────────────────

@pytest.fixture
def make_env_config(env_parser):
    """
    Factory fixture: returns a function that parses raw .env text.

    Usage:
        def test_something(make_env_config):
            config = make_env_config("DATABASE_PASSWORD=admin123\\n")
            assert config.is_valid
    """
    def _make(content: str, filename: str = "test.env"):
        return env_parser.parse(content, filename)
    return _make


@pytest.fixture
def make_yaml_config(yaml_parser):
    """Factory fixture for YAML config objects."""
    def _make(content: str, filename: str = "test.yaml"):
        return yaml_parser.parse(content, filename)
    return _make


@pytest.fixture
def make_json_config(json_parser):
    """Factory fixture for JSON config objects."""
    def _make(content: str, filename: str = "test.json"):
        return json_parser.parse(content, filename)
    return _make


# ── Issue / Fix helper ────────────────────────────────────────────────────────

@pytest.fixture
def make_issue():
    """
    Factory fixture: creates a minimal SecurityIssue for testing.

    Usage:
        def test_blue_team(make_issue):
            issue = make_issue("CRED-001", "DATABASE_PASSWORD=admin123")
            ...
    """
    def _make(
        rule_id: str,
        vulnerable_code: str,
        severity: str = "high",
        line_number: int = 1,
        category: str = "credentials",
        file_name: str = "test.env",
        template_id: str = None,
    ):
        from models.issue_model import SecurityIssue
        from models.risk_model import RiskProfile

        rp = RiskProfile(
            base_severity=7.5,
            exploitability=0.8,
            impact_confidentiality="high",
            impact_integrity="medium",
            impact_availability="low",
            likelihood_mean=0.70,
            likelihood_std=0.15,
        )

        # Derive template_id from rule_id if not given
        if template_id is None:
            prefix = rule_id.split("-")[0]   # e.g. CRED, ENC, AC
            num    = rule_id.split("-")[-1]  # e.g. 001
            template_id = f"{prefix}-FIX-{num}"

        return SecurityIssue(
            issue_id=f"test-{rule_id}",
            rule_id=rule_id,
            rule_name=f"Test rule {rule_id}",
            category=category,
            severity=severity,
            cvss_score=7.5,
            title=f"Test issue {rule_id}",
            description="Synthetic test issue.",
            file_name=file_name,
            line_number=line_number,
            vulnerable_code=vulnerable_code,
            risk_profile=rp,
            remediation_hint="Fix this vulnerability.",
            template_id=template_id,
            nist_function="PROTECT",
            nist_category="PR.AC-1",
            cwe_id="CWE-798",
        )

    return _make


# ── Analyzer fixture ──────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def analyzer(rules_dir):
    """Return a RedTeamAnalyzer loaded with the real rule catalog."""
    from src.core.red_team.analyzer import RedTeamAnalyzer
    return RedTeamAnalyzer(rules_dir=rules_dir)


@pytest.fixture(scope="session")
def remediator(templates_dir):
    """Return a BlueTeamRemediator loaded with the real template catalog."""
    from src.core.blue_team.remediator import BlueTeamRemediator
    return BlueTeamRemediator(templates_dir=templates_dir)


@pytest.fixture(scope="session")
def simulator():
    """Return a MonteCarloSimulator with a small iteration count for fast tests."""
    from src.core.simulation.monte_carlo import MonteCarloSimulator
    return MonteCarloSimulator(iterations=500, seed=42)
