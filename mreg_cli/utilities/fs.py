"""File system utilities."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from mreg_cli.exceptions import InputFailure

logger = logging.getLogger(__name__)


def get_writable_file_or_tempfile(path: Path) -> Path:
    """Ensure a file path exists and is writable, otherwise return a temporary file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_dir():
            raise IsADirectoryError(f"Path {path} is a directory, not a file")
        # Check write privileges without overwriting existing content
        if path.exists():
            # Test write access on existing file by opening in append mode
            with path.open("a"):
                pass
        else:
            # Create new file if it doesn't exist
            path.touch()
    except OSError as e:
        import tempfile  # noqa: PLC0415 # only import if we really need it
        import time  # noqa: PLC0415

        # NOTE: we might not be able to write to the temp file either
        # but in that case we are so far outside the normal
        # usage patterns that we should probably just fail
        tmpfile = Path(tempfile.gettempdir()) / path.name or f"mreg-cli-temp-{int(time.time())}"
        logger.error(
            "Unable to create file at %s due to: %s; falling back to temporary file at %s",
            path,
            e,
            tmpfile,
        )
        tmpfile.touch()
        return tmpfile
    return path


def to_path(value: Any) -> Path:
    """Convert a value to a Path object with expanded user and resolved symlinks."""
    try:
        p = Path(value)
        try:
            p = p.expanduser()
        except RuntimeError:  # no homedir
            pass
        return p.resolve()
    except Exception as e:
        raise InputFailure(f"Invalid path {value}: {e}") from e
