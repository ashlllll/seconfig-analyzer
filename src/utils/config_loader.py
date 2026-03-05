"""
config_loader.py
~~~~~~~~~~~~~~~~
Load and expose application configuration from ``config.yaml``.

The configuration is loaded **once** and cached; subsequent calls to
``get_config()`` return the same dictionary.  Unit tests may call
``reset_config()`` to force a fresh reload.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

import yaml

from src.utils.logger import get_logger

log = get_logger(__name__)

# Default config file location (project root)
_DEFAULT_CONFIG_PATH = "config.yaml"

# Module-level cache
_config: Optional[dict[str, Any]] = None
_config_path: Optional[str] = None


# ---------------------------------------------------------------------------
# Defaults – used when a key is missing from config.yaml
# ---------------------------------------------------------------------------
_DEFAULTS: dict[str, Any] = {
    "app": {
        "name": "SecConfig Analyzer",
        "version": "1.0.0",
        "debug": False,
        "log_level": "INFO",
    },
    "analysis": {
        "supported_formats": ["env", "yaml", "yml", "json"],
        "max_file_size_mb": 10,
        "rules_dir": "data/rules_catalog",
        "templates_dir": "data/templates_catalog",
        "parallel_processing": False,
        "max_workers": 4,
    },
    "red_team": {
        "enabled_rules": "all",
        "severity_threshold": "low",
        "cache_compiled_regex": True,
    },
    "blue_team": {
        "auto_fix_enabled": True,
        "backup_original": True,
        "validation_strict": True,
    },
    "simulation": {
        "default_iterations": 10_000,
        "confidence_level": 0.95,
        "seed": 42,
        "default_distribution": "beta",
        "use_multiprocessing": False,
    },
    "llm": {
        "enabled": False,
        "provider": "openai",
        "model": "gpt-4",
        "api_key_env": "OPENAI_API_KEY",
        "temperature": 0.8,
        "max_tokens": 500,
        "presence_penalty": 0.6,
        "frequency_penalty": 0.6,
        "max_requests_per_minute": 10,
    },
    "ui": {
        "theme": "light",
        "page_title": "SecConfig Analyzer",
        "page_icon": "🔒",
        "issues_per_page": 10,
        "chart_height": 400,
        "chart_template": "plotly_white",
    },
    "logging": {
        "level": "INFO",
        "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        "file": "logs/app.log",
        "rotation": "daily",
        "retention_days": 30,
    },
    "export": {
        "pdf_font": "Helvetica",
        "json_indent": 2,
        "csv_delimiter": ",",
    },
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    """
    Recursively merge *override* into *base* (non-destructive copy).

    Keys present in *override* take precedence; nested dicts are merged
    recursively rather than replaced wholesale.
    """
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_from_file(config_path: str) -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        log.warning(
            "Config file '%s' not found – using built-in defaults.", config_path
        )
        return {}

    with path.open(encoding="utf-8") as fh:
        raw = yaml.safe_load(fh) or {}

    log.info("Loaded configuration from '%s'.", config_path)
    return raw


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_config(config_path: str = _DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """
    Load configuration from *config_path*, merge with defaults, and cache.

    Parameters
    ----------
    config_path:
        Path to the YAML configuration file.

    Returns
    -------
    dict
        Fully populated configuration dictionary.
    """
    global _config, _config_path

    raw = _load_from_file(config_path)
    _config = _deep_merge(_DEFAULTS, raw)
    _config_path = config_path

    # Honour environment-variable overrides for sensitive settings
    _apply_env_overrides(_config)

    return _config


def get_config(config_path: str = _DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """
    Return the cached configuration, loading it first if necessary.
    """
    global _config
    if _config is None:
        load_config(config_path)
    return _config  # type: ignore[return-value]


def reset_config() -> None:
    """Clear the module-level cache (useful in tests)."""
    global _config, _config_path
    _config = None
    _config_path = None


# ---------------------------------------------------------------------------
# Convenience accessors
# ---------------------------------------------------------------------------

def get(key: str, default: Any = None) -> Any:
    """
    Retrieve a top-level configuration value by *key*.

    Parameters
    ----------
    key:
        Top-level key (e.g. ``"simulation"``).
    default:
        Returned when *key* is absent.
    """
    return get_config().get(key, default)


def get_nested(section: str, key: str, default: Any = None) -> Any:
    """
    Retrieve a nested configuration value.

    Parameters
    ----------
    section:
        Top-level section name (e.g. ``"simulation"``).
    key:
        Key within that section (e.g. ``"default_iterations"``).
    default:
        Returned when either *section* or *key* is absent.
    """
    return get_config().get(section, {}).get(key, default)


# ---------------------------------------------------------------------------
# Environment-variable overrides
# ---------------------------------------------------------------------------

def _apply_env_overrides(config: dict[str, Any]) -> None:
    """
    Patch sensitive config values with environment variables when set.

    Supported env vars
    ------------------
    ``SECCONFIG_LOG_LEVEL``
        Overrides ``logging.level``.
    ``SECCONFIG_LLM_ENABLED``
        Set to ``"true"`` / ``"1"`` to enable LLM explainer.
    ``OPENAI_API_KEY``
        Automatically picked up by the LLM module (not stored in config).
    ``SECCONFIG_MC_ITERATIONS``
        Override Monte Carlo iteration count.
    """
    log_level = os.getenv("SECCONFIG_LOG_LEVEL")
    if log_level:
        config.setdefault("logging", {})["level"] = log_level.upper()

    llm_enabled = os.getenv("SECCONFIG_LLM_ENABLED", "").lower()
    if llm_enabled in {"true", "1", "yes"}:
        config.setdefault("llm", {})["enabled"] = True

    mc_iterations = os.getenv("SECCONFIG_MC_ITERATIONS")
    if mc_iterations and mc_iterations.isdigit():
        config.setdefault("simulation", {})["default_iterations"] = int(mc_iterations)
