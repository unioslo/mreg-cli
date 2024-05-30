"""Metadata about the mreg-cli package."""

from __future__ import annotations

import subprocess
from pathlib import Path

__version__ = "1.0.0"


def _git_rev_parse(*args: str) -> subprocess.CompletedProcess[str]:
    """Run `git rev-parse` with the given arguments in the mreg-cli directory."""
    p = Path(__file__).parent
    return subprocess.run(
        ["git", "-C", str(p), "rev-parse", *args],
        check=True,
        capture_output=True,
        text=True,
    )


def is_from_git() -> bool:
    """Check if the current mreg-cli installation comes from git."""
    try:
        proc = _git_rev_parse("--is-inside-work-tree")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    else:
        # If working tree is empty, git returns "false" (with code 0[?])
        # https://stackoverflow.com/questions/2180270/check-if-current-directory-is-a-git-repository#comment77714402_16925062
        if "true" in proc.stdout:
            return True
        return False


def get_git_commit() -> str:
    """Get the git commit hash of the current mreg-cli installation."""
    try:
        proc = _git_rev_parse("HEAD")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""
    else:
        return proc.stdout.strip()


def get_version_extended() -> str:
    """Get the mreg-cli version with git commit hash if available."""
    if is_from_git():
        return f"{__version__} (git: {get_git_commit()})"
    return __version__
