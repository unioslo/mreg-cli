"""Host-related utilities."""

import argparse
import ipaddress
import re
import urllib.parse
from typing import Any, Dict, Optional, Tuple, Union

from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliWarning, HostNotFoundWarning
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.types import IP_Version
from mreg_cli.utilities.api import get, get_list, patch, post
from mreg_cli.utilities.network import (
    get_network,
    get_network_by_ip,
    get_network_first_unused_ip,
    get_network_reserved_ips,
)
from mreg_cli.utilities.shared import format_mac
from mreg_cli.utilities.validators import (
    is_valid_ip,
    is_valid_ipv4,
    is_valid_ipv6,
    is_valid_mac,
    is_valid_network,
)


def clean_hostname(name: Union[str, bytes]) -> str:
    """Convert from short to long hostname, if no domain found."""
    # bytes?
    if not isinstance(name, (str, bytes)):
        cli_warning("Invalid input for hostname: {}".format(name))

    if isinstance(name, bytes):
        name = name.decode()

    name = name.lower()

    # invalid characters?
    if re.search(r"^(\*\.)?([a-z0-9_][a-z0-9\-]*\.?)+$", name) is None:
        cli_warning("Invalid input for hostname: {}".format(name))

    # Assume user is happy with domain, but strip the dot.
    if name.endswith("."):
        return name[:-1]

    # If a dot in name, assume long name.
    if "." in name:
        return name

    config = MregCliConfig()
    default_domain = config.get("domain")
    # Append domain name if in config and it does not end with it
    if default_domain and not name.endswith(default_domain):
        return "{}.{}".format(name, default_domain)
    return name


def get_unique_ip_by_name_or_ip(arg: str) -> Dict[str, Any]:
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
            cli_warning(f"ip {arg} doesn't exist.")
        elif len(ips) > 1:
            cli_warning("ip {} is in use by {} hosts".format(arg, len(ips)))
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
                "{} has multiple addresses in the same address family.".format(arg)
                + " Please specify a specific address to use instead."
            )

        net1 = get_network_by_ip(ip1)
        net2 = get_network_by_ip(ip2)
        if net1["vlan"] and net2["vlan"] and net1["vlan"] == net2["vlan"]:
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
            "{} doesn't have any ip addresses.".format(arg),
            raise_exception=True,
            exception=CliWarning,
        )
    ip = info["ipaddresses"][0]
    return ip


def assoc_mac_to_ip(mac: str, ip: Dict[str, Any], force: bool = False) -> Union[str, None]:
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
        cli_warning("invalid MAC address: {}".format(mac))

    old_mac = ip.get("macaddress")
    if old_mac == new_mac:
        cli_info("new and old mac are identical. Ignoring.", print_msg=True)
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


def add_ip_to_host(
    args: argparse.Namespace, ipversion: IP_Version, macaddress: Optional[str] = None
) -> None:
    """Add an A record to host. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, ip, force)
    :param ipversion: 4 or 6
    :param macaddress: macaddress to associate with the ip (optional)
    """
    info = None

    if "*" in args.name and not args.force:
        cli_warning("Wildcards must be forced.")

    ip = get_requested_ip(args.ip, args.force, ipversion=ipversion)

    try:
        # Get host info for or raise exception
        info = host_info_by_name(args.name)
    except HostNotFoundWarning:
        pass

    if macaddress is not None:
        if is_valid_mac(macaddress):
            macaddress = format_mac(macaddress)
        else:
            cli_error(f"Invalid macaddress: {macaddress}")

    if info is None:
        hostname = clean_hostname(args.name)
        data = {"name": hostname, "ipaddress": ip}
        # Create new host with IP
        path = "/api/v1/hosts/"
        post(path, params=None, **data)
        cli_info(f"Created host {hostname} with ip {ip}", print_msg=True)
        if macaddress is not None:
            # It can only be one, as it was just created.
            new_ip = get(f"{path}{hostname}").json()["ipaddresses"][0]
            assoc_mac_to_ip(macaddress, new_ip, force=args.force)

    else:
        # Require force if host has multiple A/AAAA records
        if len(info["ipaddresses"]) and not args.force:
            cli_warning("{} already has A/AAAA record(s), must force".format(info["name"]))

        if any(args.ip == i["ipaddress"] for i in info["ipaddresses"]):
            cli_warning(f"Host already has IP {args.ip}")

        data = {
            "host": info["id"],
            "ipaddress": ip,
        }
        if macaddress is not None:
            data["macaddress"] = macaddress

        # Add IP
        path = "/api/v1/ipaddresses/"
        post(path, params=None, **data)
        cli_info(f"added ip {ip} to {info['name']}", print_msg=True)


def get_requested_ip(ip: str, force: bool, ipversion: Union[IP_Version, None] = None) -> str:
    """Return an IP address from the given args.

    - If the given ip is an ip, then that ip is returned.
    - If the given ip is a network, then the first unused IP from that network is returned.
    - If the given ip is a network without a mask, then network is deduced as per above.

    Note that the ipversion is only used to check that the given ip is of the correct version.
    """
    # Try to fail fast for valid IP
    if ipversion is not None and is_valid_ip(ip):
        if ipversion == 4:
            # Fail if input isn't ipv4
            if is_valid_ipv6(ip):
                cli_warning("got ipv6 address, want ipv4.")
            if not is_valid_ipv4(ip):
                cli_warning(f"not valid ipv4 address: {ip}")
        elif ipversion == 6:
            # Fail if input isn't ipv6
            if is_valid_ipv4(ip):
                cli_warning("got ipv4 address, want ipv6.")
            if not is_valid_ipv6(ip):
                cli_warning(f"not valid ipv6 address: {ip}")

    # Handle arbitrary ip from network if received a network w/o mask
    if ip.endswith("/"):
        network = get_network(ip[:-1])
        ip = get_network_first_unused_ip(network)
    # Handle arbitrary ip from network if received a network w/mask
    elif is_valid_network(ip):
        network = get_network(ip)
        ip = get_network_first_unused_ip(network)
    elif is_valid_ip(ip):
        path = "/api/v1/hosts/"
        hosts = get_list(path, params={"ipaddresses__ipaddress": ip})
        if hosts and not force:
            hostnames = ",".join([i["name"] for i in hosts])
            cli_warning(f"{ip} already in use by: {hostnames}. Must force")
        network = get_network_by_ip(ip)
        if not network:
            if force:
                return ip
            cli_warning(f"{ip} isn't in a network controlled by MREG, must force")
    else:
        cli_warning(f"Could not determine network for {ip}")

    network_object = ipaddress.ip_network(network["network"])
    if ipversion:
        if network_object.version != ipversion:
            if ipversion == 4:
                cli_warning("Attemptet to get an ipv4 address, but input yielded ipv6")
            elif ipversion == 6:
                cli_warning("Attemptet to get an ipv6 address, but input yielded ipv4")

    if network["frozen"] and not force:
        cli_warning("network {} is frozen, must force".format(network["network"]))
    # Chat the address given isn't reserved
    reserved_addresses = get_network_reserved_ips(network["network"])
    if ip in reserved_addresses and not force:
        cli_warning("Address is reserved. Requires force")
    if network_object.num_addresses > 2:
        if ip == network_object.network_address.exploded:
            cli_warning("Can't overwrite the network address of the network")
        if ip == network_object.broadcast_address.exploded:
            cli_warning("Can't overwrite the broadcast address of the network")

    return ip


def host_info_by_name_or_ip(name_or_ip: str) -> Dict[str, Any]:
    """Return a dict with host information about the given host, or the host owning the given ip.

    :param name_or_ip: Either a host name on short or long form or an ipv4/ipv6 address.
    :return: A dict of the JSON object received with the host information
    """
    if is_valid_ip(name_or_ip):
        name = resolve_ip(name_or_ip)
    else:
        name = name_or_ip
    return host_info_by_name(name)


def _host_info_by_name(name: str, follow_cname: bool = True) -> Optional[Dict[str, Any]]:
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


def host_info_by_name(name: str, follow_cname: bool = True) -> Dict[str, Any]:
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
        cli_warning(f"host not found: {name!r}", exception=HostNotFoundWarning)

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
        cli_error('resolve ip got multiple matches for ip "{}"'.format(ip))

    if len(hosts) == 0:
        cli_warning("{} doesnt belong to any host".format(ip), exception=HostNotFoundWarning)
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
    cli_warning("host not found: {}".format(name), exception=HostNotFoundWarning)


def _cname_info_by_name(name: str) -> Optional[Dict[str, Any]]:
    """Return a dict with information about the given cname."""
    path = "/api/v1/cnames/"
    params = {
        "name": name,
    }
    info = get_list(path, params=params)
    if len(info) == 1:
        return info[0]
    return None


def _srv_info_by_name(name: str) -> Optional[Dict[str, Any]]:
    """Return a dict with information about the given srv."""
    path = "/api/v1/srvs/"
    params = {
        "name": name,
    }
    info = get_list(path, params=params)
    if len(info) == 1:
        return info[0]
    return None


def get_info_by_name(name: str) -> Tuple[str, Dict[str, Any]]:
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
    cli_warning(f"not found: {name!r}", exception=HostNotFoundWarning)
