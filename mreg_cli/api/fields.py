"""Fields for models of the API."""

from __future__ import annotations

import ipaddress
from typing import Annotated, Any, Self

from pydantic import BeforeValidator, ValidationError
from pydantic_extra_types.mac_address import MacAddress

from mreg_cli.api.abstracts import FrozenModel
from mreg_cli.exceptions import InputFailure
from mreg_cli.types import IP_AddressT


class MACAddressField(FrozenModel):
    """Represents a MAC address."""

    address: MacAddress

    @classmethod
    def validate(cls, value: str | MacAddress | Self) -> Self:
        """Validate a MAC address and return it as a string."""
        try:
            return cls.validate_naive(value)
        except ValueError as e:
            raise InputFailure(e) from e

    # HACK: extremely hacky workaround for our custom exceptions always
    # logging errors/warnings even when caught.
    @classmethod
    def validate_naive(cls, value: str | MacAddress | Self) -> Self:
        """Validate but raise built-in exceptions on failure."""
        if isinstance(value, MACAddressField):
            return cls.validate_naive(value.address)
        try:
            return cls(address=value)  # pyright: ignore[reportArgumentType]
        except ValidationError as e:
            raise ValueError(f"Invalid MAC address '{value}'") from e

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


def _extract_name(value: dict[str, Any]) -> str:
    """Extract the name from the dictionary.

    :param v: Dictionary containing the name.
    :returns: Extracted name as a string.
    """
    return value["name"]


NameList = list[Annotated[str, BeforeValidator(_extract_name)]]
