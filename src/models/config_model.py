"""
Configuration File Data Model
Represents a parsed configuration file and its metadata.
"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List


@dataclass
class ConfigFile:
    """
    Data model for an uploaded configuration file.

    Stores the raw content, parsed content, and metadata
    extracted from .env, .yaml, or .json files.
    """

    # ── Basic Information ──────────────────────────────────────────────────────
    file_name: str
    file_type: str          # 'env' | 'yaml' | 'json'
    file_size: int          # in bytes
    upload_timestamp: datetime

    # ── Content ───────────────────────────────────────────────────────────────
    raw_content: str
    parsed_content: Dict[str, Any]  # flat or nested key-value pairs

    # ── Metadata ──────────────────────────────────────────────────────────────
    encoding: str = 'utf-8'
    line_count: int = 0

    # ── Validation ────────────────────────────────────────────────────────────
    is_valid: bool = True
    parse_errors: List[str] = field(default_factory=list)

    # ── Deduplication ─────────────────────────────────────────────────────────
    content_hash: str = ""

    def __post_init__(self):
        """Auto-calculate line count if not provided."""
        if self.line_count == 0 and self.raw_content:
            self.line_count = len(self.raw_content.splitlines())

    @property
    def file_size_kb(self) -> float:
        """Return file size in kilobytes."""
        return round(self.file_size / 1024, 2)

    @property
    def has_errors(self) -> bool:
        """Return True if there are parse errors."""
        return len(self.parse_errors) > 0

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for reporting."""
        return {
            "file_name": self.file_name,
            "file_type": self.file_type,
            "file_size_kb": self.file_size_kb,
            "line_count": self.line_count,
            "encoding": self.encoding,
            "is_valid": self.is_valid,
            "parse_errors": self.parse_errors,
            "upload_timestamp": self.upload_timestamp.isoformat(),
        }

    def __repr__(self) -> str:
        return (
            f"ConfigFile(name={self.file_name!r}, "
            f"type={self.file_type!r}, "
            f"lines={self.line_count}, "
            f"valid={self.is_valid})"
        )
