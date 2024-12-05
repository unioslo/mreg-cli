"""Fields for models of the API."""

from __future__ import annotations

import logging
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator
from pydantic_extra_types.mac_address import MacAddress as PydanticMacAddress

from mreg_cli.exceptions import InputFailure
from mreg_cli.types import get_type_adapter

logger = logging.getLogger(__name__)


class MacAddress(PydanticMacAddress):
    """MAC address string type used in Pydantic models."""

    @classmethod
    def parse(cls, obj: Any) -> MacAddress | None:
        """Parse a MAC address from a string. Returns None if the MAC address is invalid.

        :param obj: The object to parse.
        :returns: The MAC address as a string or None if it is invalid.
        """
        try:
            return cls.parse_or_raise(obj)
        except InputFailure:
            return None

    @classmethod
    def parse_or_raise(cls, obj: Any) -> MacAddress:
        """Parse a MAC address from a string. Returns the MAC address as a string.

        :param obj: The object to parse.
        :returns: The MAC address as a string.
        :raises ValueError: If the object is not a valid MAC address.
        """
        try:
            adapter = get_type_adapter(cls)
            # Convert regular string to MacAddress string after validation.
            # The pydantic validator returns a regular string even though the
            # Pydantic MacAddress type is a distinct type that subclasses str.
            # By converting the string to a MacAddress string, we can distinguish
            # between a valid MAC address and a valid string at runtime if needed.
            return cls(adapter.validate_python(obj))
        except ValueError as e:
            raise InputFailure(f"Invalid MAC address '{obj}'") from e


def _extract_name(value: Any) -> str:
    """Extract the "name" value from a dictionary.

    :param v: Dictionary containing the name.
    :returns: Extracted name as a string.
    """
    if isinstance(value, dict):
        try:
            return str(value["name"])  # pyright: ignore[reportUnknownArgumentType]
        except KeyError:
            logger.error("No 'name' key in %s", value)  # pyright: ignore[reportUnknownArgumentType]
            return ""
    return value


def _remove_falsy_list_items(value: Any) -> Any:
    """Remove falsy items from a list.

    For use in validators only.
    """
    if isinstance(value, list):
        return [i for i in value if i]  # pyright: ignore[reportUnknownVariableType]
    return value


NameList = Annotated[
    list[Annotated[str, BeforeValidator(_extract_name)]],
    AfterValidator(_remove_falsy_list_items),
]
"""List of names extracted from a list of dicts."""
