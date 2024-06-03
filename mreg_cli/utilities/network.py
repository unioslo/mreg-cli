"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

from __future__ import annotations

import ipaddress
import urllib.parse
from collections.abc import Iterable
from typing import Any

from mreg_cli.api.models import Network
from mreg_cli.exceptions import EntityNotFound, EntityOwnershipMismatch, InputFailure
from mreg_cli.types import IP_networkTV
from mreg_cli.utilities.api import get, get_typed
from mreg_cli.utilities.validators import is_valid_ip, is_valid_network


def get_network(ip: str) -> Network | None:
    """Return a network associated with given range or IP."""
    if is_valid_network(ip):
        path = f"/api/v1/networks/{urllib.parse.quote(ip)}"
        return get(path).json()
    elif is_valid_ip(ip):
        net = Network.get_by_ip(ipaddress.ip_address(ip))
        if net:
            return net
        raise EntityOwnershipMismatch(
            "ip address exists but is not an address in any existing network"
        )
    else:
        raise InputFailure("Not a valid ip range or ip address")


def get_network_reserved_ips(ip_range: str) -> list[str]:
    """Return the first unused address on a network, if any."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/reserved_list"
    return get_typed(path, list[str])
