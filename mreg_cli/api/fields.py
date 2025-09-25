"""Custom field types for Pydantic models.

The types validate to basic types like str, int, etc., but with additional
validation added to them. The types are used in Pydantic models for consistent
validation of common fields such as hostnames, MAC addresses, etc.

Warning:
Values constructed from these types should NOT be checked at runtime with isinstance()!
Pydantic will always coerce these types to their schema types (str, int, etc.).

"""

from __future__ import annotations

import logging
import re
from typing import Annotated, Any

from pydantic import AfterValidator, BeforeValidator, GetCoreSchemaHandler
from pydantic_core import core_schema
from pydantic_extra_types.mac_address import MacAddress as PydanticMacAddress

from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import InputFailure
from mreg_cli.types import get_type_adapter

logger = logging.getLogger(__name__)


class HostName(str):
    """Hostname string type."""

    @classmethod
    def parse(cls, obj: Any) -> HostName | None:
        """Parse a hostname from a string. Returns None if the hostname is invalid.

        :param obj: The object to parse.
        :returns: The hostname as a string or None if it is invalid.
        """
        try:
            return cls.parse_or_raise(obj)
        except InputFailure:
            return None

    @classmethod
    def parse_or_raise(cls, obj: Any) -> HostName:
        """Parse a hostname from a string. Returns the hostname as a string.

        :param obj: The object to parse.
        :returns: The hostname as a string.
        :raises ValueError: If the object is not a valid hostname.
        """
        try:
            adapter = get_type_adapter(cls)
            return cls(adapter.validate_python(obj))
        except ValueError as e:
            raise InputFailure(f"Invalid hostname '{obj}'") from e

    @staticmethod
    def validate_hostname(value: str) -> str:
        """Validate the hostname."""
        value = value.lower()

        if re.search(r"^(\*\.)?([a-z0-9_][a-z0-9\-]*\.?)+$", value) is None:
            raise InputFailure(f"Invalid input for hostname: {value}")

        # Assume user is happy with domain, but strip the dot.
        if value.endswith("."):
            return value[:-1]

        # If a dot in name, assume long name.
        if "." in value:
            return value

        config = MregCliConfig()
        domain = config.domain
        # Append domain name if in config and it does not end with it
        if domain and not value.endswith(domain):
            return f"{value}.{domain}"
        return value

    @classmethod
    def __get_pydantic_core_schema__(
        cls, source: type[Any], handler: GetCoreSchemaHandler
    ) -> core_schema.CoreSchema:
        """Return a Pydantic CoreSchema with the hostname validation.

        :param source: The source type to be converted.
        :param handler: The handler to get the CoreSchema.
        :returns: A Pydantic CoreSchema with the hostname validation.

        """
        return core_schema.with_info_before_validator_function(
            cls._validate,
            core_schema.str_schema(),
        )

    @classmethod
    def _validate(cls, __input_value: str, _: Any) -> str:
        """Validate a hostname from the provided str value.

        Args:
            __input_value: The str value to be validated.
            _: The source type to be converted.

        Returns:
            str: The parsed hostname.

        """
        return cls.validate_hostname(__input_value)


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
