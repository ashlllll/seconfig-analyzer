"""
constants.py
~~~~~~~~~~~~
Application-wide constants for SecConfig Analyzer.
"""

# ---------------------------------------------------------------------------
# Severity levels (ordered lowest → highest)
# ---------------------------------------------------------------------------
SEVERITY_LEVELS = ["info", "low", "medium", "high", "critical"]

SEVERITY_WEIGHTS: dict[str, int] = {
    "info":     0,
    "low":      1,
    "medium":   2,
    "high":     3,
    "critical": 4,
}

SEVERITY_COLOURS: dict[str, str] = {
    "info":     "#6c757d",  # grey
    "low":      "#28a745",  # green
    "medium":   "#ffc107",  # amber
    "high":     "#fd7e14",  # orange
    "critical": "#dc3545",  # red
}

# ---------------------------------------------------------------------------
# NIST Cybersecurity Framework functions
# ---------------------------------------------------------------------------
NIST_FUNCTIONS = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]

NIST_FUNCTION_DESCRIPTIONS: dict[str, str] = {
    "IDENTIFY": "Develop organisational understanding to manage cybersecurity risk.",
    "PROTECT":  "Implement appropriate safeguards to ensure delivery of critical services.",
    "DETECT":   "Implement appropriate activities to identify the occurrence of a cybersecurity event.",
    "RESPOND":  "Implement appropriate activities to take action regarding a detected cybersecurity incident.",
    "RECOVER":  "Implement appropriate activities to maintain plans for resilience.",
}

# ---------------------------------------------------------------------------
# Issue categories
# ---------------------------------------------------------------------------
ISSUE_CATEGORIES = [
    "credentials",
    "encryption",
    "access_control",
    "logging",
    "baseline",
]

# ---------------------------------------------------------------------------
# Supported configuration file formats
# ---------------------------------------------------------------------------
SUPPORTED_FILE_TYPES = ["env", "yaml", "yml", "json"]

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# ---------------------------------------------------------------------------
# Monte Carlo defaults
# ---------------------------------------------------------------------------
MC_DEFAULT_ITERATIONS  = 10_000
MC_DEFAULT_SEED        = 42
MC_CONFIDENCE_LEVEL    = 0.95

# ---------------------------------------------------------------------------
# Risk score boundaries (0-100 scale)
# ---------------------------------------------------------------------------
RISK_THRESHOLDS: dict[str, tuple[float, float]] = {
    "critical": (80.0, 100.0),
    "high":     (60.0,  79.9),
    "medium":   (40.0,  59.9),
    "low":      (20.0,  39.9),
    "info":     ( 0.0,  19.9),
}

# ---------------------------------------------------------------------------
# CIA impact mapping (string label → numeric weight)
# ---------------------------------------------------------------------------
CIA_IMPACT_WEIGHTS: dict[str, float] = {
    "high":   1.0,
    "medium": 0.6,
    "low":    0.3,
    "none":   0.0,
}

# ---------------------------------------------------------------------------
# Fix types
# ---------------------------------------------------------------------------
FIX_TYPES = ["automated", "semi_automated", "manual"]

FIX_STRATEGIES = [
    "template_replacement",
    "value_encryption",
    "configuration_change",
    "removal",
    "manual_guidance",
]

# ---------------------------------------------------------------------------
# Issue / fix status
# ---------------------------------------------------------------------------
ISSUE_STATUSES = ["detected", "reviewing", "fixing", "fixed", "ignored"]
FIX_STATUSES   = ["pending", "validated", "failed", "applied"]

# ---------------------------------------------------------------------------
# LLM / explainer
# ---------------------------------------------------------------------------
LLM_DEFAULT_MODEL       = "gpt-4"
LLM_DEFAULT_TEMPERATURE = 0.8
LLM_MAX_TOKENS          = 500
LLM_PRESENCE_PENALTY    = 0.6
LLM_FREQUENCY_PENALTY   = 0.6

USER_BACKGROUNDS = ["junior_dev", "manager", "security_expert"]

# ---------------------------------------------------------------------------
# Paths (relative to project root)
# ---------------------------------------------------------------------------
DEFAULT_RULES_DIR     = "data/rules_catalog"
DEFAULT_TEMPLATES_DIR = "data/templates_catalog"
DEFAULT_RESULTS_DIR   = "data/results"
LOG_DIR               = "logs"
LOG_FILE              = "logs/app.log"

# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------
REPORT_PDF_FONT   = "Helvetica"
REPORT_JSON_INDENT = 2
REPORT_CSV_DELIMITER = ","

# ---------------------------------------------------------------------------
# UI
# ---------------------------------------------------------------------------
ISSUES_PER_PAGE  = 10
CHART_HEIGHT     = 400
CHART_TEMPLATE   = "plotly_white"
PAGE_TITLE       = "SecConfig Analyzer"
PAGE_ICON        = "🔒"
