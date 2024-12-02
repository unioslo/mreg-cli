"""Fields for models of the API."""

from __future__ import annotations

import ipaddress
import logging
from typing import Annotated, Any, Self

from pydantic import AfterValidator, BeforeValidator, ValidationError
from pydantic_extra_types.mac_address import MacAddress

from mreg_cli.api.abstracts import FrozenModel
from mreg_cli.exceptions import InputFailure
from mreg_cli.types import IP_AddressT

logger = logging.getLogger(__name__)


class MACAddressField(FrozenModel):
    """Represents a MAC address."""

    address: MacAddress

    # HACK: extremely hacky workaround for our custom exceptions always
    # logging errors/warnings even when caught.
    @classmethod
    def validate(cls, value: str | MacAddress | Self) -> Self:
        """Validate but raise built-in exceptions on failure."""
        if isinstance(value, MACAddressField):
            return cls.validate(value.address)
        try:
            return cls(address=value)  # pyright: ignore[reportArgumentType]
        except ValidationError as e:
            raise InputFailure(f"Invalid MAC address '{value}'") from e

    @classmethod
    def parse_or_raise(cls, obj: Any) -> MacAddress:
        """Parse a MAC address from a string. Returns the MAC address as a string.

        :param obj: The object to parse.
        :returns: The MAC address as a string.
        :raises ValueError: If the object is not a valid MAC address.
        """
        # Match interface of NetworkOrIP.parse_or_raise
        return cls.validate(obj).address

    @classmethod
    def parse(cls, obj: Any) -> MacAddress | None:
        """Parse a MAC address from a string. Returns None if the MAC address is invalid.

        :param obj: The object to parse.
        :returns: The MAC address as a string or None if it is invalid.
        """
        try:
            return cls.parse_or_raise(obj)
        except ValueError:
            return None

    def __str__(self) -> str:
        """Return the MAC address as a string."""
        return str(self.address)


class IPAddressField(FrozenModel):
    """Represents an IP address, automatically determines if it's IPv4 or IPv6."""

    address: IP_AddressT

    @classmethod
    def validate(cls, value: str | IP_AddressT | Self) -> IPAddressField:
        """Construct an IPAddressField from a string.

        Handles validation and exception handling for creating an IPAddressField.
        """
        if isinstance(value, IPAddressField):
            return cls.validate(value.address)
        try:
            return cls(address=value)  # pyright: ignore[reportArgumentType] # validator handles this
        except ValueError as e:
            raise InputFailure(f"Invalid IP address '{value}'.") from e

    def is_ipv4(self) -> bool:
        """Check if the IP address is IPv4."""
        return isinstance(self.address, ipaddress.IPv4Address)

    def is_ipv6(self) -> bool:
        """Check if the IP address is IPv6."""
        return isinstance(self.address, ipaddress.IPv6Address)

    @staticmethod
    def is_valid(value: str) -> bool:
        """Check if the value is a valid IP address."""
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def __str__(self) -> str:
        """Return the IP address as a string."""
        return str(self.address)

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash(self.address)


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
