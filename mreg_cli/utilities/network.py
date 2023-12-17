"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

import ipaddress
import os
import sys
from typing import TYPE_CHECKING, Any, Dict, Iterable, List, NoReturn

if TYPE_CHECKING:
    pass

import urllib.parse

from mreg_cli.log import cli_warning
from mreg_cli.utilities.api import get
from mreg_cli.utilities.validators import is_valid_ip, is_valid_network


def error(msg: str, code: int = os.EX_UNAVAILABLE) -> NoReturn:
    """Print an error message and exits with the given code."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def get_network_first_unused_ip(network: Dict[str, Any]) -> str:
    """Return the first unused ip from a given network.

    Assumes network exists.
    :param network: dict with network info (key: "network").
    :return: Ip address string.
    """
    unused = get_network_first_unused(network["network"])
    if not unused:
        cli_warning("No free addresses remaining on network {}".format(network["network"]))
    return unused


def ip_in_mreg_net(ip: str) -> bool:
    """Return true if the ip is in a MREG controlled network."""
    net = get_network_by_ip(ip)
    return bool(net)


def ipsort(ips: Iterable[Any]) -> List[Any]:
    """Sort a list of ips."""
    return sorted(ips, key=lambda i: ipaddress.ip_address(i))


def get_network_by_ip(ip: str) -> Dict[str, Any]:
    """Return a network associated with given IP."""
    if is_valid_ip(ip):
        path = f"/api/v1/networks/ip/{urllib.parse.quote(ip)}"
        net = get(path, ok404=True)
        if net:
            return net.json()
        else:
            return {}
    else:
        cli_warning("Not a valid ip address")


def get_network(ip: str) -> Dict[str, Any]:
    """Return a network associated with given range or IP."""
    if is_valid_network(ip):
        path = f"/api/v1/networks/{urllib.parse.quote(ip)}"
        return get(path).json()
    elif is_valid_ip(ip):
        net = get_network_by_ip(ip)
        if net:
            return net
        cli_warning("ip address exists but is not an address in any existing network")
    else:
        cli_warning("Not a valid ip range or ip address")


def get_network_used_count(ip_range: str) -> int:
    """Return a count of the addresses in use on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/used_count"
    return get(path).json()


def get_network_used_list(ip_range: str) -> List[str]:
    """Return a list of the addresses in use on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/used_list"
    return get(path).json()


def get_network_unused_count(ip_range: str) -> int:
    """Return a count of the unused addresses on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/unused_count"
    return get(path).json()


def get_network_unused_list(ip_range: str) -> List[str]:
    """Return a list of the unused addresses on a given network."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/unused_list"
    return get(path).json()


def get_network_first_unused(ip_range: str) -> str:
    """Return the first unused address on a network, if any."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/first_unused"
    return get(path).json()


def get_network_reserved_ips(ip_range: str) -> List[str]:
    """Return the first unused address on a network, if any."""
    path = f"/api/v1/networks/{urllib.parse.quote(ip_range)}/reserved_list"
    return get(path).json()
