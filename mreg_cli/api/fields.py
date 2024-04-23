"""Fields for models of the API."""

import ipaddress
import re

from pydantic import validator

from mreg_cli.api.abstracts import FrozenModel
from mreg_cli.types import IP_AddressT

_mac_regex = re.compile(r"^([0-9A-Fa-f]{2}[.:-]){5}([0-9A-Fa-f]{2})$")


class MACAddressField(FrozenModel):
    """Represents a MAC address."""

    address: str

    @validator("address", pre=True)
    def validate_and_format_mac(cls, v: str) -> str:
        """Validate and normalize MAC address to 'aa:bb:cc:dd:ee:ff' format.

        :param v: The input MAC address string.
        :raises ValueError: If the input does not match the expected MAC address pattern.
        :returns: The normalized MAC address.
        """
        # Validate input format
        if not _mac_regex.match(v):
            raise ValueError("Invalid MAC address format")

        # Normalize MAC address
        v = re.sub(r"[.:-]", "", v).lower()
        return ":".join(v[i : i + 2] for i in range(0, 12, 2))

    def __str__(self) -> str:
        """Return the MAC address as a string."""
        return self.address


class IPAddressField(FrozenModel):
    """Represents an IP address, automatically determines if it's IPv4 or IPv6."""

    address: IP_AddressT

    @validator("address", pre=True)
    def parse_ip_address(cls, value: str) -> IP_AddressT:
        """Parse and validate the IP address."""
        try:
            return ipaddress.ip_address(value)
        except ValueError as e:
            raise ValueError(f"Invalid IP address '{value}'.") from e

    def is_ipv4(self) -> bool:
        """Check if the IP address is IPv4."""
        return isinstance(self.address, ipaddress.IPv4Address)

    def is_ipv6(self) -> bool:
        """Check if the IP address is IPv6."""
        return isinstance(self.address, ipaddress.IPv6Address)

    def __str__(self) -> str:
        """Return the IP address as a string."""
        return str(self.address)

    def __hash__(self):
        """Return a hash of the IP address."""
        return hash(self.address)
