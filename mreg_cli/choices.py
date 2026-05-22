"""Choices for various command arguments."""

from __future__ import annotations

from enum import StrEnum


class _ChoiceBase(StrEnum):
    @classmethod
    def metavar(cls) -> str:
        """Get a string representation of the choices for use in metavar."""
        return f"<{'|'.join([choice.value for choice in cls])}>"


class CommunitySortOrder(_ChoiceBase):
    """Sort order for communities."""

    NAME = "name"
    GLOBAL_NAME = "global"
