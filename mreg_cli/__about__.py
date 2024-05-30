"""Metadata about the mreg-cli package."""

from __future__ import annotations


def _get_scm_version() -> str:
    try:
        from mreg_cli._version import version
    except ImportError:
        return __version__
    return version


def _get_version_tuple() -> tuple[str | int, ...] | None:
    try:
        from mreg_cli._version import version_tuple
    except ImportError:
        return tuple(map(int, __version__.split(".")))
    return version_tuple


__version__ = "1.0.0"
__version_tuple__ = _get_version_tuple()


def get_version_extended() -> str:
    """Get the mreg-cli version with git commit hash if available."""
    return _get_scm_version()
