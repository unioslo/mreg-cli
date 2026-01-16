"""Shared output utilities."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from mreg_cli.exceptions import InternalError
from mreg_cli.outputmanager import OutputManager

if TYPE_CHECKING:
    pass


class HasTimestamps(Protocol):
    """Protocol for objects with timestamp fields."""

    created_at: datetime
    updated_at: datetime


class HasTTL(Protocol):
    """Protocol for objects with TTL field."""

    ttl: int | None


def output_timestamps(
    obj: HasTimestamps,
    padding: int = 14,
    created_label: str = "Created:",
    updated_label: str = "Updated:",
) -> None:
    """Output created/updated timestamps.

    :param obj: Object with created_at and updated_at fields.
    :param padding: Number of spaces for left-padding the labels.
    :param created_label: Label for the created timestamp.
    :param updated_label: Label for the updated timestamp.
    """
    manager = OutputManager()
    manager.add_line(f"{created_label:<{padding}}{obj.created_at:%c}")
    manager.add_line(f"{updated_label:<{padding}}{obj.updated_at:%c}")


def output_ttl(
    obj: Any,
    label: str = "TTL",
    field: str = "ttl",
    padding: int = 14,
) -> None:
    """Output a TTL value.

    :param obj: Object with a TTL field.
    :param label: Label to display for the TTL.
    :param field: The field name containing the TTL value (defaults to 'ttl').
    :param padding: Number of spaces for left-padding the output.
    """
    if not hasattr(obj, field):
        raise InternalError(f"TTL field {field} not found in object.")

    ttl_value = getattr(obj, field)
    label = f"{label.removesuffix(':')}:"
    OutputManager().add_line(f"{label:<{padding}}{ttl_value or '(Default)'}")
