"""
Pattern Matcher
Low-level regex and keyword matching utilities for the Red Team engine.
"""
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class MatchResult:
    """
    Represents a single pattern match found in a config file.
    """
    line_number: int
    line_content: str
    matched_text: str
    column_start: int
    column_end: int
    pattern_used: str

    @property
    def vulnerable_code(self) -> str:
        """Return the matched line stripped of whitespace."""
        return self.line_content.strip()

    def __repr__(self) -> str:
        return (
            f"MatchResult(line={self.line_number}, "
            f"match={self.matched_text!r})"
        )


class Matcher:
    """
    Handles low-level regex pattern matching against config file content.

    Used by the RuleEngine to find vulnerable patterns line by line.
    """

    def __init__(self):
        # Cache compiled regex patterns for performance
        self._compiled_cache: dict = {}

    def compile_pattern(self, pattern: str) -> re.Pattern:
        """
        Compile and cache a regex pattern.

        Args:
            pattern: Regex pattern string

        Returns:
            Compiled regex pattern
        """
        if pattern not in self._compiled_cache:
            try:
                self._compiled_cache[pattern] = re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        return self._compiled_cache[pattern]

    def match_line(
        self,
        line: str,
        line_number: int,
        patterns: List[str],
    ) -> Optional[MatchResult]:
        """
        Try to match any of the given patterns against a single line.

        Args:
            line:        The line content to check
            line_number: Line number (1-based)
            patterns:    List of regex patterns to try

        Returns:
            MatchResult if any pattern matches, None otherwise
        """
        for pattern in patterns:
            compiled = self.compile_pattern(pattern)
            match = compiled.search(line)

            if match:
                return MatchResult(
                    line_number=line_number,
                    line_content=line,
                    matched_text=match.group(0),
                    column_start=match.start(),
                    column_end=match.end(),
                    pattern_used=pattern,
                )

        return None

    def is_excluded(self, line: str, exclusion_patterns: List[str]) -> bool:
        """
        Check if a line matches any exclusion pattern.

        Exclusions are used to reduce false positives — for example,
        a line like DATABASE_PASSWORD=${DB_PASS} should not be flagged.

        Args:
            line:               The line content to check
            exclusion_patterns: List of regex patterns that indicate safe usage

        Returns:
            True if the line should be excluded (i.e., is safe)
        """
        for pattern in exclusion_patterns:
            compiled = self.compile_pattern(pattern)
            if compiled.search(line):
                return True
        return False

    def get_context(
        self,
        lines: List[str],
        line_number: int,
        context_size: int = 2,
    ) -> tuple:
        """
        Get lines before and after a matched line for context display.

        Args:
            lines:        All lines in the file
            line_number:  The matched line number (1-based)
            context_size: Number of context lines on each side

        Returns:
            (context_before, context_after) as joined strings
        """
        idx = line_number - 1  # convert to 0-based index
        total = len(lines)

        start = max(0, idx - context_size)
        end = min(total, idx + context_size + 1)

        before_lines = lines[start:idx]
        after_lines = lines[idx + 1:end]

        context_before = "\n".join(
            f"{start + i + 1} | {l}"
            for i, l in enumerate(before_lines)
        )
        context_after = "\n".join(
            f"{idx + i + 2} | {l}"
            for i, l in enumerate(after_lines)
        )

        return context_before, context_after

    def scan_content(
        self,
        content: str,
        patterns: List[str],
        exclusion_patterns: List[str] = None,
    ) -> List[MatchResult]:
        """
        Scan all lines of content for pattern matches.

        Args:
            content:            Raw file content
            patterns:           Patterns to search for
            exclusion_patterns: Patterns that mark a line as safe

        Returns:
            List of MatchResult objects for all matched lines
        """
        if exclusion_patterns is None:
            exclusion_patterns = []

        results = []
        lines = content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            # Skip empty lines and comment-only lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check exclusions first
            if self.is_excluded(line, exclusion_patterns):
                continue

            # Try to match
            match = self.match_line(line, line_number, patterns)
            if match:
                results.append(match)

        return results
