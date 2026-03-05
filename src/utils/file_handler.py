"""
file_handler.py
~~~~~~~~~~~~~~~
File I/O helpers for SecConfig Analyzer.

All public functions are intentionally side-effect free where possible:
they read/write only what they are asked to and never modify global state.
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from src.utils.logger import get_logger

log = get_logger(__name__)

# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------

def read_text_file(file_path: str | Path, encoding: str = "utf-8") -> str:
    """
    Read and return the full contents of a text file.

    Parameters
    ----------
    file_path:
        Absolute or relative path to the file.
    encoding:
        Character encoding (default ``utf-8``).

    Returns
    -------
    str
        The raw file content.

    Raises
    ------
    FileNotFoundError
        When *file_path* does not exist.
    IOError
        On any other read error.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    try:
        content = path.read_text(encoding=encoding)
        log.debug("Read %d bytes from '%s'", len(content), path)
        return content
    except Exception as exc:
        raise IOError(f"Failed to read '{path}': {exc}") from exc


def read_json_file(file_path: str | Path) -> Any:
    """
    Read a JSON file and return the parsed Python object.

    Raises
    ------
    FileNotFoundError | json.JSONDecodeError | IOError
    """
    raw = read_text_file(file_path)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise json.JSONDecodeError(
            f"Invalid JSON in '{file_path}': {exc.msg}", exc.doc, exc.pos
        ) from exc


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------

def write_text_file(
    file_path: str | Path,
    content: str,
    encoding: str = "utf-8",
    create_parents: bool = True,
) -> Path:
    """
    Write *content* to *file_path*, optionally creating parent directories.

    Returns
    -------
    Path
        Resolved path of the written file.
    """
    path = Path(file_path)

    if create_parents:
        path.parent.mkdir(parents=True, exist_ok=True)

    try:
        path.write_text(content, encoding=encoding)
        log.debug("Wrote %d bytes to '%s'", len(content), path)
        return path.resolve()
    except Exception as exc:
        raise IOError(f"Failed to write '{path}': {exc}") from exc


def write_json_file(
    file_path: str | Path,
    data: Any,
    indent: int = 2,
    create_parents: bool = True,
) -> Path:
    """
    Serialise *data* as JSON and write to *file_path*.

    Returns
    -------
    Path
        Resolved path of the written file.
    """
    content = json.dumps(data, indent=indent, ensure_ascii=False, default=str)
    return write_text_file(file_path, content, create_parents=create_parents)


# ---------------------------------------------------------------------------
# File metadata
# ---------------------------------------------------------------------------

def get_file_info(file_path: str | Path) -> dict[str, Any]:
    """
    Return a dictionary with basic metadata for *file_path*.

    Keys: ``name``, ``extension``, ``size_bytes``, ``line_count``,
    ``encoding``, ``modified_at``.
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    stat = path.stat()
    content = path.read_bytes()

    # Attempt to detect encoding (simple heuristic)
    try:
        content.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        encoding = "latin-1"

    text = content.decode(encoding, errors="replace")
    line_count = len(text.splitlines())

    return {
        "name":         path.name,
        "extension":    path.suffix.lstrip(".").lower(),
        "size_bytes":   stat.st_size,
        "line_count":   line_count,
        "encoding":     encoding,
        "modified_at":  datetime.fromtimestamp(stat.st_mtime).isoformat(),
    }


# ---------------------------------------------------------------------------
# Directory helpers
# ---------------------------------------------------------------------------

def list_files(
    directory: str | Path,
    extensions: Optional[list[str]] = None,
    recursive: bool = False,
) -> list[Path]:
    """
    List files in *directory*, optionally filtered by *extensions*.

    Parameters
    ----------
    directory:
        Directory to scan.
    extensions:
        Whitelist of file extensions **without** leading dot,
        e.g. ``["yaml", "yml"]``.  ``None`` = all files.
    recursive:
        When ``True``, search subdirectories as well.

    Returns
    -------
    list[Path]
        Sorted list of matching file paths.
    """
    dir_path = Path(directory)
    if not dir_path.is_dir():
        raise NotADirectoryError(f"Not a directory: {dir_path}")

    pattern = "**/*" if recursive else "*"
    all_files = [p for p in dir_path.glob(pattern) if p.is_file()]

    if extensions:
        normalised = {ext.lstrip(".").lower() for ext in extensions}
        all_files = [p for p in all_files if p.suffix.lstrip(".").lower() in normalised]

    return sorted(all_files)


def ensure_directory(directory: str | Path) -> Path:
    """Create *directory* (and any parents) if it does not already exist."""
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True)
    return path


def safe_copy(src: str | Path, dst: str | Path, overwrite: bool = False) -> Path:
    """
    Copy *src* to *dst*.

    Parameters
    ----------
    overwrite:
        When ``False`` (default), raise ``FileExistsError`` if *dst* exists.

    Returns
    -------
    Path
        Resolved destination path.
    """
    src_path = Path(src)
    dst_path = Path(dst)

    if not src_path.exists():
        raise FileNotFoundError(f"Source file not found: {src_path}")

    if dst_path.exists() and not overwrite:
        raise FileExistsError(f"Destination already exists: {dst_path}")

    dst_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_path, dst_path)
    log.debug("Copied '%s' → '%s'", src_path, dst_path)
    return dst_path.resolve()


# ---------------------------------------------------------------------------
# Result persistence helpers
# ---------------------------------------------------------------------------

def save_analysis_result(
    result_data: dict[str, Any],
    output_dir: str | Path = "data/results",
    file_name: Optional[str] = None,
) -> Path:
    """
    Persist an analysis result dictionary as a timestamped JSON file.

    Parameters
    ----------
    result_data:
        Serialisable dictionary (use ``dataclasses.asdict()`` if needed).
    output_dir:
        Directory where the file will be saved.
    file_name:
        Custom file name (without extension).  Defaults to a timestamp.

    Returns
    -------
    Path
        Path to the saved file.
    """
    ensure_directory(output_dir)

    if file_name is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        file_name = f"analysis_{timestamp}"

    output_path = Path(output_dir) / f"{file_name}.json"
    return write_json_file(output_path, result_data)
