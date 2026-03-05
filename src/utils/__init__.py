"""
src/utils
~~~~~~~~~
Utility layer for SecConfig Analyzer.

Public surface
--------------
from src.utils import get_logger, get_config, constants
"""

from src.utils.logger import get_logger, get_app_logger, configure_root_logger
from src.utils.config_loader import get_config, load_config, get_nested, reset_config
from src.utils.validator import (
    validate_file_type,
    validate_file_size,
    validate_file_content,
    validate_severity,
    validate_nist_function,
    validate_category,
    validate_probability,
    validate_risk_score,
    validate_rule_dict,
    validate_template_dict,
    compute_content_hash,
    sanitise_string,
    is_placeholder_value,
)
from src.utils.file_handler import (
    read_text_file,
    read_json_file,
    write_text_file,
    write_json_file,
    get_file_info,
    list_files,
    ensure_directory,
    safe_copy,
    save_analysis_result,
)
from src.utils import constants

__all__ = [
    # Logger
    "get_logger",
    "get_app_logger",
    "configure_root_logger",
    # Config
    "get_config",
    "load_config",
    "get_nested",
    "reset_config",
    # Validator
    "validate_file_type",
    "validate_file_size",
    "validate_file_content",
    "validate_severity",
    "validate_nist_function",
    "validate_category",
    "validate_probability",
    "validate_risk_score",
    "validate_rule_dict",
    "validate_template_dict",
    "compute_content_hash",
    "sanitise_string",
    "is_placeholder_value",
    # File handler
    "read_text_file",
    "read_json_file",
    "write_text_file",
    "write_json_file",
    "get_file_info",
    "list_files",
    "ensure_directory",
    "safe_copy",
    "save_analysis_result",
    # Constants module
    "constants",
]
