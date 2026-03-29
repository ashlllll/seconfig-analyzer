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


# Keys whose values are never secrets — used to suppress false positives
# from description/hint/comment-style YAML fields.
_SAFE_KEY_PREFIXES = (
    "description",
    "hint",
    "comment",
    "label",
    "title",
    "name",
    "message",
    "example",
    "note",
    "text",
    "help",
    "info",
    "url",        # URL values may contain "password" in path segments
    "link",
    "doc",
)

# Regex to extract the key from a "key = value" or "key: value" line
_KEY_EXTRACT_RE = re.compile(
    r'^\s*(?:export\s+)?([A-Za-z_]\w*)\s*(?:=|:)', re.IGNORECASE
)


def _is_safe_key(line: str) -> bool:
    """
    Return True when the config key on this line is a known non-secret field.

    This prevents false positives on YAML description/hint lines that happen
    to contain words like "password" or "secret" in their prose values.

    FIX: Addresses the false-positive bug where lines such as
        description: "A password is hard-coded in the configuration file."
    were being flagged as vulnerabilities.
    """
    m = _KEY_EXTRACT_RE.match(line)
    if not m:
        return False
    key = m.group(1).lower()
    return any(key.startswith(prefix) for prefix in _SAFE_KEY_PREFIXES)


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
                flags = 0
                normalized = pattern

                # Some catalog regexes embed (?i) mid-pattern, which Python
                # rejects. Normalize by stripping inline case flags and using
                # IGNORECASE globally.
                if "(?i)" in normalized:
                    flags |= re.IGNORECASE
                    normalized = normalized.replace("(?i)", "")

                self._compiled_cache[pattern] = re.compile(normalized, flags)
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
        # FIX: Skip lines whose key is a known non-secret field.
        # This prevents prose descriptions in YAML from triggering rules.
        if _is_safe_key(line):
            return None

        # Try original line first, then normalised variants to support
        # JSON/YAML key quoting and ":" assignments.
        candidates = [line]

        # Strip surrounding quotes (handles JSON "key": "value" style)
        no_quotes = line.replace('"', '').replace("'", "")
        if no_quotes != line:
            candidates.append(no_quotes)

        # Rewrite YAML-style "key: value" → "key=value", but ONLY for lines
        # that look like a simple config assignment.  A blanket replace(":"," =")
        # would corrupt URLs ("https://..."), timestamps, and port numbers.
        _kv_match = re.match(
            r'^(\s*(?:export\s+)?[A-Za-z_]\w*)\s*:\s*(.*)$', line
        )
        if _kv_match:
            with_equals = f"{_kv_match.group(1)}={_kv_match.group(2)}"
            if with_equals not in candidates:
                candidates.append(with_equals)

            # Also try the quote-stripped variant of the rewritten form
            no_quotes_equals = with_equals.replace('"', '').replace("'", "")
            if no_quotes_equals not in candidates:
                candidates.append(no_quotes_equals)

        for pattern in patterns:
            compiled = self.compile_pattern(pattern)
            for candidate in candidates:
                match = compiled.search(candidate)
                if match:
                    return MatchResult(
                        line_number=line_number,
                        line_content=line,
                        matched_text=match.group(0),
                        column_start=match.start() if candidate == line else 0,
                        column_end=match.end() if candidate == line else len(line),
                        pattern_used=pattern,
                    )

        return None

    def is_excluded(self, line: str, exclusion_patterns: List[str]) -> bool:
        """
        Check if a line matches any exclusion pattern.

        Exclusions are used to reduce false positives — for example,
        a line like DATABASE_PASSWORD=${DB_PASS} should not be flagged.

        FIX: Exclusion patterns that are just '(?i)#' (matching any line
        containing a hash) previously suppressed lines with inline comments
        such as:
            DATABASE_PASSWORD=admin123  # TODO: change this
        These lines ARE vulnerable and should NOT be excluded.

        The fix: only apply the bare '#' exclusion pattern against the
        VALUE portion of the line (after the '='), not the whole line.
        This preserves the intent (skip comment-only values like
        SOME_KEY=#placeholder) while not hiding real secrets with comments.

        Args:
            line:               The line content to check
            exclusion_patterns: List of regex patterns that indicate safe usage

        Returns:
            True if the line should be excluded (i.e., is safe)
        """
        for pattern in exclusion_patterns:
            compiled = self.compile_pattern(pattern)

            # FIX: For bare comment patterns (only '#' or whitespace around it),
            # test against the value portion only so that inline comments on
            # vulnerable lines don't suppress the finding.
            stripped_pattern = pattern.replace("(?i)", "").strip()
            is_comment_pattern = stripped_pattern in ("#", r"(?i)#")

            if is_comment_pattern:
                # Extract value after '=' or ':' to check
                value_match = re.match(
                    r'^\s*[A-Za-z_]\w*\s*(?:=|:)\s*(.*)', line
                )
                target = value_match.group(1).strip() if value_match else line
                # Only exclude if the VALUE itself is a comment/placeholder
                if target.startswith("#"):
                    return True
            else:
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
            # Skip empty lines
            stripped = line.strip()
            if not stripped:
                continue

            # Skip pure comment lines (entire line is a comment).
            # FIX: Only skip lines where '#' is the FIRST non-whitespace
            # character. Do NOT skip lines that merely contain '#' somewhere
            # (e.g. inline comments after a value) — those may still be
            # vulnerable and must be evaluated.
            if stripped.startswith("#"):
                continue

            # Check exclusions first
            if self.is_excluded(line, exclusion_patterns):
                continue

            # Try to match
            match = self.match_line(line, line_number, patterns)
            if match:
                results.append(match)

        return results