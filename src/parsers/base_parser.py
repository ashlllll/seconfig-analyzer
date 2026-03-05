"""
Base Parser - Abstract Base Class
All config file parsers inherit from this class.
"""
import hashlib
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict, List, Tuple

from ..models.config_model import ConfigFile


class BaseParser(ABC):
    """
    Abstract base class for all configuration file parsers.

    Subclasses must implement:
        - parse()
        - validate()
    """

    # ── Abstract Methods ──────────────────────────────────────────────────────

    @abstractmethod
    def parse(self, content: str, file_name: str) -> ConfigFile:
        """
        Parse raw file content into a ConfigFile object.

        Args:
            content:   Raw string content of the file
            file_name: Original filename (e.g. 'app.env')

        Returns:
            ConfigFile object with parsed_content populated
        """
        pass

    @abstractmethod
    def validate(self, content: str) -> Tuple[bool, List[str]]:
        """
        Validate the format of raw file content.

        Args:
            content: Raw string content of the file

        Returns:
            (is_valid, list_of_error_messages)
        """
        pass

    # ── Shared Helper Methods ─────────────────────────────────────────────────

    def get_file_type(self) -> str:
        """Return the file type this parser handles. Override in subclass."""
        return "unknown"

    def compute_hash(self, content: str) -> str:
        """Compute SHA-256 hash of content for deduplication."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def extract_lines(self, content: str) -> List[str]:
        """Split content into lines, preserving empty lines."""
        return content.splitlines()

    def count_lines(self, content: str) -> int:
        """Count total number of lines in content."""
        return len(content.splitlines())

    def get_file_size(self, content: str) -> int:
        """Return file size in bytes."""
        return len(content.encode("utf-8"))

    def _build_config_file(
        self,
        file_name: str,
        content: str,
        parsed_content: Dict[str, Any],
        is_valid: bool = True,
        parse_errors: List[str] = None,
    ) -> ConfigFile:
        """
        Helper to construct a ConfigFile object with common fields filled.

        Args:
            file_name:      Name of the file
            content:        Raw file content
            parsed_content: Parsed key-value pairs
            is_valid:       Whether parsing succeeded
            parse_errors:   List of error messages if any

        Returns:
            ConfigFile object
        """
        return ConfigFile(
            file_name=file_name,
            file_type=self.get_file_type(),
            file_size=self.get_file_size(content),
            upload_timestamp=datetime.now(),
            raw_content=content,
            parsed_content=parsed_content,
            line_count=self.count_lines(content),
            is_valid=is_valid,
            parse_errors=parse_errors or [],
            content_hash=self.compute_hash(content),
        )
