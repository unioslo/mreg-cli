"""File system utilities."""

from __future__ import annotations

import logging
import os
import functools
from pathlib import Path
from typing import Any

from mreg_cli.exceptions import InputFailure

logger = logging.getLogger(__name__)


def get_writable_file_or_tempfile(path: Path) -> Path:
    """Ensure a writable file path exists, creating it if necessary, or fall back to a temporary file.

    :param path: The desired file path.
    :returns: The original path if writable, otherwise a temporary file path.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.is_dir():
            raise IsADirectoryError(f"Path {path} is a directory, not a file")
        if path.exists():
            check_writable(path)
        else:
            # Create new file if it doesn't exist (very defensively)
            path.touch(exist_ok=True)
    except OSError as e:
        import time  # noqa: PLC0415

        logger.error(
            "Unable to create file at %s: %s",
            path,
            e,
        )

        filename = path.name or f"mreg-cli-temp-{int(time.time())}"
        # NOTE: Not really a temporary dir, since we never delete it!
        tempdir = get_temp_dir()
        tmpfile = tempdir / filename
        try:
            tmpfile.touch(exist_ok=True)
            check_writable(tmpfile)
        except Exception as tmp_err:
            raise OSError(f"Unable to create temporary file at {tmpfile}: {tmp_err}") from tmp_err
        logger.warning("Using temporary file at %s", tmpfile)
        return tmpfile
    return path


def check_writable(path: Path) -> None:
    """Check if the given path is writable.

    HACKY: Tests write access on file by opening in append mode.
    """
    # Check write privileges without overwriting existing content
    with path.open("a"):
        pass


@functools.cache
def get_temp_dir() -> Path:
    """Get a temporary directory for use by the CLI.

    Always returns the same directory for the lifetime of the process.
    """
    import tempfile  # noqa: PLC0415

    temp_dir = tempfile.mkdtemp(prefix="mreg-cli.", suffix="." + str(os.getuid()))
    return Path(temp_dir)


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
