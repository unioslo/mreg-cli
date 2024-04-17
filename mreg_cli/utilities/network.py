"""Utility functions for mreg_cli.

Due to circular dependencies, this module is not allowed to import anything from mreg_cli.
And this rule is promptly broken by importing from mreg_cli.outputmanager...
"""

import ipaddress
import sys
import urllib.parse
from typing import Any, Dict, Iterable, List

from mreg_cli.api import get_network_by_ip
from mreg_cli.log import cli_warning
from mreg_cli.types import IP_networkT


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
    ipt = ipaddress.ip_address(ip)
    net = get_network_by_ip(ipt)
    return bool(net)


def ipsort(ips: Iterable[Any]) -> List[Any]:
    """Sort a list of ips."""
    return sorted(ips, key=lambda i: ipaddress.ip_address(i))


def ips_are_in_same_vlan(ips: List[str]) -> bool:
    """Return True if all ips are in the same vlan."""
    # IPs must be in a network, and that network must have a vlan for this to work.
    last_vlan = ""
    for ip in ips:
        network = get_network_by_ip(ipaddress.ip_address(ip))
        if not network:
            return False

        if "vlan" not in network:
            return False

        if last_vlan and network["vlan"] != last_vlan:
            return False

        last_vlan = network["vlan"]

    return True


def get_network(ip: str) -> Dict[str, Any]:
    """Return a network associated with given range or IP."""
    if is_valid_network(ip):
        path = f"/api/v1/networks/{urllib.parse.quote(ip)}"
        return get(path).json()
    elif is_valid_ip(ip):
        net = get_network_by_ip(ipaddress.ip_address(ip))
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


def network_is_supernet(a: IP_networkT, b: IP_networkT) -> bool:
    """Return True if a is a supernet of b."""
    if sys.version_info >= (3, 7):
        return a.supernet_of(b)
    else:
        return (
            a.network_address <= b.network_address and a.broadcast_address >= b.broadcast_address
        )
