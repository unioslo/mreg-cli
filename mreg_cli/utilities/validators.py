"""Utility functions for mreg_cli.

Due to circular dependencies, be very aware of what you import here.

"""

import ipaddress
import re
from typing import TYPE_CHECKING, Union

from mreg_cli.config import MregCliConfig
from mreg_cli.log import cli_warning
from mreg_cli.types import IP_Version

if TYPE_CHECKING:
    pass


def is_valid_ip(ip: str) -> bool:
    """Check if ip is valid ipv4 og ipv6."""
    return is_valid_ipv4(ip) or is_valid_ipv6(ip)


def is_valid_ipv4(ip: str) -> bool:
    """Check if ip is valid ipv4."""
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_ipv6(ip: str) -> bool:
    """Check if ip is valid ipv6."""
    try:
        ipaddress.IPv6Address(ip)
    except ValueError:
        return False
    else:
        return True


def is_valid_network(net: str) -> bool:
    """Check if net is a valid network."""
    if is_valid_ip(net):
        return False
    try:
        ipaddress.ip_network(net)
        return True
    except ValueError:
        return False


def is_valid_mac(mac: str) -> bool:
    """Check if mac is a valid MAC address."""
    return bool(re.match(r"^([a-fA-F0-9]{2}[\.:-]?){5}[a-fA-F0-9]{2}$", mac))


def is_valid_ttl(ttl: Union[int, str, bytes]) -> bool:  # int?
    """Check application specific ttl restrictions."""
    if ttl in ("", "default"):
        return True
    if not isinstance(ttl, int):
        try:
            ttl = int(ttl)
        except ValueError:
            return False
    return 300 <= ttl <= 68400


def is_valid_email(email: Union[str, bytes]) -> bool:
    """Check if email looks like a valid email."""
    if not isinstance(email, str):
        try:
            email = email.decode()
        except ValueError:
            return False
    return True if re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email) else False


def is_valid_location_tag(loc: str) -> bool:
    """Check if valid location tag."""
    return loc in MregCliConfig().get("location_tags", [])


def is_valid_category_tag(cat: str) -> bool:
    """Check if valid location tag."""
    return cat in MregCliConfig().get("category_tags", [])


def is_ipversion(ip: str, ipversion: IP_Version) -> None:
    """Check that the given ip is of the given ipversion."""
    # Ip sanity check
    if ipversion == 4:
        if not is_valid_ipv4(ip):
            cli_warning(f"not a valid ipv4: {ip}")
    elif ipversion == 6:
        if not is_valid_ipv6(ip):
            cli_warning(f"not a valid ipv6: {ip}")
    else:
        cli_warning(f"Unknown ipversion: {ipversion}")
