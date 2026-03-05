"""
logger.py
~~~~~~~~~
Centralised logging utility for SecConfig Analyzer.

Usage
-----
from src.utils.logger import get_logger

log = get_logger(__name__)
log.info("Analysis started")
log.warning("Suspicious pattern found at line %d", line_no)
log.error("Parser failed: %s", exc)
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path
from typing import Optional

from src.utils.constants import LOG_DIR, LOG_FILE

# ---------------------------------------------------------------------------
# Internal registry – one logger instance per name
# ---------------------------------------------------------------------------
_loggers: dict[str, logging.Logger] = {}

# Default format shared by all handlers
_FORMATTER = logging.Formatter(
    fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _build_console_handler(level: int) -> logging.StreamHandler:
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(level)
    handler.setFormatter(_FORMATTER)
    return handler


def _build_file_handler(
    log_file: str = LOG_FILE,
    level: int = logging.DEBUG,
    max_bytes: int = 5 * 1024 * 1024,  # 5 MB
    backup_count: int = 5,
) -> logging.handlers.RotatingFileHandler:
    """Rotating file handler – creates parent directories automatically."""
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(_FORMATTER)
    return handler


def configure_root_logger(
    console_level: str = "INFO",
    file_level: str = "DEBUG",
    log_file: str = LOG_FILE,
    enable_file_logging: bool = True,
) -> None:
    """
    Call once at application start-up (e.g. in ``app.py``).

    Parameters
    ----------
    console_level:
        Minimum severity to print to stdout (``DEBUG`` | ``INFO`` | ``WARNING`` | ``ERROR``).
    file_level:
        Minimum severity written to the rotating log file.
    log_file:
        Path to the log file (will be created if absent).
    enable_file_logging:
        Set to ``False`` in testing environments to avoid disk writes.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # let handlers filter independently

    # Avoid adding duplicate handlers when Streamlit reloads the module
    if root.handlers:
        root.handlers.clear()

    root.addHandler(_build_console_handler(getattr(logging, console_level.upper(), logging.INFO)))

    if enable_file_logging:
        root.addHandler(_build_file_handler(log_file=log_file, level=getattr(logging, file_level.upper(), logging.DEBUG)))


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Return a named logger, creating it on first call.

    Parameters
    ----------
    name:
        Typically ``__name__`` of the calling module.
    level:
        Override the effective log level for this specific logger (optional).
    """
    if name in _loggers:
        return _loggers[name]

    logger = logging.getLogger(name)

    if level:
        logger.setLevel(getattr(logging, level.upper(), logging.DEBUG))

    _loggers[name] = logger
    return logger


# ---------------------------------------------------------------------------
# Convenience singleton used by core modules
# ---------------------------------------------------------------------------
def get_app_logger() -> logging.Logger:
    """Return the top-level application logger (``secconfig``)."""
    return get_logger("secconfig")
