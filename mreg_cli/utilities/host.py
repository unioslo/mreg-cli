"""Host-related utilities."""

from __future__ import annotations

import urllib.parse
from typing import Any

from mreg_cli.exceptions import (
    CliWarning,
    EntityNotFound,
    ForceMissing,
    InputFailure,
    MultipleEntititesFound,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.utilities.api import get, get_list, patch
from mreg_cli.utilities.network import ips_are_in_same_vlan
from mreg_cli.utilities.shared import clean_hostname, format_mac
from mreg_cli.utilities.validators import is_valid_ip, is_valid_ipv4, is_valid_ipv6, is_valid_mac


def get_unique_ip_by_name_or_ip(arg: str) -> dict[str, Any]:
    """Get A/AAAA record by either ip address or host name.

    This will fail if:
        - The host has multiple A/AAAA records and they are on different VLANs.
        - The host has no A/AAAA records.
        - The IP is used by multiple hosts.
        - The IP or host doesn't exist.

    If the host has one A and AAAA record on the same VLAN, the IPv4 address is returned.

    :param arg: ip address or host name (as a string)

    :return: A dict with the ip address information.
    """
    if is_valid_ip(arg):
        path = "/api/v1/ipaddresses/"
        params = {
            "ipaddress": arg,
        }
        ips = get_list(path, params=params)
        if not len(ips):
            raise EntityNotFound(f"ip {arg} doesn't exist.")
        elif len(ips) > 1:
            raise MultipleEntititesFound(f"ip {arg} is in use by {len(ips)} hosts")
        return ips[0]

    # We were not given an IP, so resolve as a host.
    info = host_info_by_name(arg)
    if len(info["ipaddresses"]) == 2:
        # one of these may be is_valid_ip4 and the other is_valid_ip6.
        ip1 = info["ipaddresses"][0]["ipaddress"]
        ip2 = info["ipaddresses"][1]["ipaddress"]

        if not (is_valid_ipv4(ip1) and is_valid_ipv6(ip2)) or (
            is_valid_ipv6(ip1) and is_valid_ipv4(ip2)
        ):
            cli_warning(
                f"{arg} has multiple addresses in the same address family."
                " Please specify a specific address to use instead."
            )

        if ips_are_in_same_vlan([ip1, ip2]):
            # In the case of the host having IPv4 and IPv6 on the same VLAN, we return the IPv4
            # address. This works "okay" for now as its the only DUID type they can share.
            if is_valid_ipv4(ip1):
                return info["ipaddresses"][0]
            return info["ipaddresses"][1]
        else:
            cli_warning(
                "{} has one IPv4 and one IPv6 address, but they are on different VLANs.".format(
                    info["name"]
                )
                + " Please specify a specific address to use instead."
            )

    elif len(info["ipaddresses"]) > 1:
        cli_warning(
            "{} has {} ip addresses, please enter one of the addresses instead.".format(
                info["name"],
                len(info["ipaddresses"]),
            )
        )
    if len(info["ipaddresses"]) == 0:
        cli_warning(
            f"{arg} doesn't have any ip addresses.",
            raise_exception=True,
            exception=CliWarning,
        )
    ip = info["ipaddresses"][0]
    return ip


def assoc_mac_to_ip(mac: str, ip: dict[str, Any], force: bool = False) -> str | None:
    """Associate MAC address with IP address."""
    # MAC addr sanity check
    if is_valid_mac(mac):
        new_mac = format_mac(mac)
        path = "/api/v1/ipaddresses/"
        params = {
            "macaddress": new_mac,
            "ordering": "ipaddress",
        }
        macs = get_list(path, params=params)
        ips = ", ".join([i["ipaddress"] for i in macs])
        if len(macs) and not force:
            cli_warning(
                "mac {} already in use by: {}. Use force to add {} -> {} as well.".format(
                    mac, ips, ip["ipaddress"], mac
                )
            )
    else:
        raise InputFailure(f"invalid MAC address: {mac}")

    old_mac = ip.get("macaddress")
    if old_mac == new_mac:
        OutputManager().add_line("new and old mac are identical. Ignoring.")
        return None
    elif old_mac and not force:
        cli_warning(
            "ip {} has existing mac {}. Use force to replace.".format(ip["ipaddress"], old_mac)
        )

    # Update Ipaddress with a mac
    path = f"/api/v1/ipaddresses/{ip['id']}"
    patch(path, macaddress=new_mac)
    return new_mac


def cname_exists(cname: str) -> bool:
    """Check if a cname exists."""
    if len(get_list("/api/v1/cnames/", params={"name": cname})):
        return True
    else:
        return False


def host_info_by_name_or_ip(name_or_ip: str) -> dict[str, Any]:
    """Return a dict with host information about the given host, or the host owning the given ip.

    :param name_or_ip: Either a host name on short or long form or an ipv4/ipv6 address.
    :return: A dict of the JSON object received with the host information
    """
    if is_valid_ip(name_or_ip):
        name = resolve_ip(name_or_ip)
    else:
        name = name_or_ip
    return host_info_by_name(name)


def _host_info_by_name(name: str, follow_cname: bool = True) -> dict[str, Any] | None:
    hostinfo = get(f"/api/v1/hosts/{urllib.parse.quote(name)}", ok404=True)

    if hostinfo:
        return hostinfo.json()
    elif follow_cname:
        # All host info data is returned from the API
        path = "/api/v1/hosts/"
        params = {"cnames__name": name}
        hosts = get_list(path, params=params)
        if len(hosts) == 1:
            return hosts[0]
    return None


def host_info_by_name(name: str, follow_cname: bool = True) -> dict[str, Any]:
    """Return a dict with host information about the given host.

    :param name: A host name on either short or long form.
    :param follow_cname: Indicate whether or not to check if name is a cname. If True (default)
    if will attempt to get the host via the cname.
    :return: A dict of the JSON object received with the host information
    """
    # Get longform of name
    name = clean_hostname(name)
    hostinfo = _host_info_by_name(name, follow_cname=follow_cname)
    if hostinfo is None:
        raise ForceMissing(f"host not found: {name!r}", exception=EntityNotFound)

    return hostinfo


def resolve_name_or_ip(name_or_ip: str) -> str:
    """Try to find a host from the given name/ip. Raises an exception if not."""
    if is_valid_ip(name_or_ip):
        return resolve_ip(name_or_ip)
    else:
        return get_host_by_name(name_or_ip)


def resolve_ip(ip: str) -> str:
    """Return a host name associated with ip."""
    path = "/api/v1/hosts/"
    params = {
        "ipaddresses__ipaddress": ip,
    }
    hosts = get_list(path, params=params)

    # Response data sanity check
    if len(hosts) > 1:
        raise MultipleEntititesFound(f'resolve ip got multiple matches for ip "{ip}"')

    if len(hosts) == 0:
        raise EntityNotFound(f"{ip} doesnt belong to any host")
    return hosts[0]["name"]


def get_host_by_name(name: str) -> str:
    """Try to find the named host. Raises an exception if not."""
    hostname = clean_hostname(name)

    path = "/api/v1/hosts/"
    params = {
        "name": hostname,
    }
    hosts = get_list(path, params=params)

    if len(hosts) == 1:
        assert hosts[0]["name"] == hostname
        return hostname
    raise EntityNotFound(f"host not found: {name}")


def _cname_info_by_name(name: str) -> dict[str, Any] | None:
    """Return a dict with information about the given cname."""
    path = "/api/v1/cnames/"
    params = {
        "name": name,
    }
    info = get_list(path, params=params)
    if len(info) == 1:
        return info[0]
    return None


def _srv_info_by_name(name: str) -> dict[str, Any] | None:
    """Return a dict with information about the given srv."""
    path = "/api/v1/srvs/"
    params = {
        "name": name,
    }
    info = get_list(path, params=params)
    if len(info) == 1:
        return info[0]
    return None


def get_info_by_name(name: str) -> tuple[str, dict[str, Any]]:
    """Get host, cname or srv by name."""
    name = clean_hostname(name)
    info = _host_info_by_name(name, follow_cname=False)
    if info is not None:
        return "host", info
    info = _cname_info_by_name(name)
    if info is not None:
        return "cname", info
    info = _srv_info_by_name(name)
    if info is not None:
        return "srv", info
    raise EntityNotFound(f"not found: {name!r}")
