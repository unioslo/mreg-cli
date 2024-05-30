"""Metadata about the mreg-cli package."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, Field

from mreg_cli._version import get_versions

__version__ = "1.0.0"

logger = logging.getLogger(__name__)


def _convert_to_str(value: Any) -> str:
    """Convert a value to a string."""
    if value is None:
        return ""
    return str(value)


ForcedStrField = Annotated[str, BeforeValidator(_convert_to_str)]
"""Field that converts everything to a string. None is converted to an empty string."""


class VersionInfo(BaseModel):
    """Model for versioneer.get_versions()."""

    date: ForcedStrField
    dirty: bool | None  # yes, this can be None if we have an error!
    error: str | None
    full_revisionid: ForcedStrField = Field(validation_alias="full-revisionid")
    version: ForcedStrField

    @classmethod
    def from_versioneer(cls) -> VersionInfo:
        """Get the version information from versioneer."""
        return cls.model_validate(get_versions())


def get_git_revision() -> str:
    """Get the git commit hash of the current mreg-cli installation."""
    try:
        v = VersionInfo.from_versioneer()
    except Exception as e:
        logger.exception(f"Failed to get version info: {e}")
        return ""
    if v.error:
        logger.error(f"Error when getting version info with versioneer: {v.error}")
        return ""
    return v.full_revisionid


def get_version_extended() -> str:
    """Get the mreg-cli version with git commit hash if available."""
    return f"{__version__} ({get_git_revision()})"
