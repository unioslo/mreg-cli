"""Utility functions for mreg_cli.

Due to circular dependencies, be very aware of what you import here.

"""

from __future__ import annotations

import ipaddress
import re

from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import InputFailure, InvalidIPv4Address, InvalidIPv6Address
from mreg_cli.types import IP_Version


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


def is_valid_location_tag(loc: str) -> bool:
    """Check if valid location tag."""
    return loc in MregCliConfig().get_location_tags()


def is_valid_category_tag(cat: str) -> bool:
    """Check if valid location tag."""
    return cat in MregCliConfig().get_category_tags()
