"""DHCP commands for mreg_cli."""

from __future__ import annotations

import argparse
import logging
from typing import Any

from mreg_api import MregClient
from mreg_api.models import Host, IPAddress, NetworkOrIP
from mreg_api.models.fields import MacAddress

from mreg_cli.client import get_client
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import (
    EntityAlreadyExists,
    EntityNotFound,
    EntityOwnershipMismatch,
    InputFailure,
    MultipleEntitiesFound,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

logger = logging.getLogger(__name__)

command_registry = CommandRegistry()


class DHCPCommands(BaseCommand):
    """DHCP commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the DHCP commands."""
        super().__init__(cli, command_registry, "dhcp", "Manage DHCP associations.", "Manage DHCP")


def ipaddress_from_ip_arg(arg: str, client: MregClient) -> IPAddress | None:
    """Get an IPAddress object from an IP address argument.

    :param arg: IP address argument.

    :returns: IPAddress object if IP is valid and exists, None if IP is invalid.

    :raises InputFailure: If the IP address is valid but does not exist.
    :raises EntityOwnershipMismatch: If the IP address is in use by multiple hosts.
    """
    if not (addr := NetworkOrIP.parse(arg, mode="ip")):
        return None

    ipobjs = client.ipaddress.list_by_ip(str(addr))
    if not ipobjs:
        raise InputFailure(f"IP address {arg} does not exist.")
    elif len(ipobjs) > 1:
        raise EntityOwnershipMismatch(f"IP {arg} is in use by {len(ipobjs)} hosts.")
    return ipobjs[0]


def ensure_macaddress_associable(mac: MacAddress, force: bool, client: MregClient) -> None:
    """Ensure that a MAC address can be associated with an IP address.

    :param mac: MacAddress object.
    :param force: Whether to force the association.
    :param client: MregClient object.

    :raises EntityAlreadyExists: If the MAC address is already associated with an IP address and force is not set.
    :raises MultipleEntitiesFound: If the MAC address is associated with multiple IP addresses and force
    """
    if force:
        return

    ips = client.ipaddress.list_by_mac(mac)
    if not ips:
        return

    if len(ips) == 1:
        raise EntityAlreadyExists(
            f"MAC address {mac} is already associated with IP address {ips[0].ipaddress}, must force."
        )
    else:
        ips_str = ", ".join([str(ip.ipaddress) for ip in ips])
        raise MultipleEntitiesFound(
            f"MAC address {mac} is already associated with multiple IP addresses: {ips_str}, must force."
        )


def get_associable_ip(host: Host, client: MregClient) -> IPAddress:
    """Get an IP address from a host that can be associated with a MAC address.

    :param host: Host object.

    :returns: IPAddress object that can be associated with a MAC address.

    :raises InputFailure: If the host has no IP addresses or multiple IP addresses.
    """
    if len(host.ipaddresses) == 0:
        raise EntityNotFound(f"Host {host.name} has no IP addresses.")

    if len(host.ipaddresses) == 1:
        return host.ipaddresses[0]

    ipv4s = host.ipv4_addresses()
    ipv6s = host.ipv6_addresses()

    if len(ipv4s) == 1 and len(ipv6s) == 1:
        ipv4_address = ipv4s[0]
        ipv6_address = ipv6s[0]
        ipv4_network = client.network.get_by_ip(ipv4_address.ipaddress)
        ipv6_network = client.network.get_by_ip(ipv6_address.ipaddress)

        if ipv4_network and ipv6_network:
            if ipv4_network.vlan == ipv6_network.vlan:
                return ipv4_address
        elif ipv4_network:  # only IPv4 is in mreg
            logger.warning(
                "Host '%s' has IPv6 address not in MREG: %s",
                host.name,
                str(ipv6_address.ipaddress),
            )
            return ipv4_address
        elif ipv6_network:  # only IPv6 is in mreg
            logger.warning(
                "Host '%s' has IPv4 address not in MREG: %s",
                host.name,
                str(ipv4_address.ipaddress),
            )
            return ipv6_address

    ips = ", ".join(str(ip.ipaddress) for ip in host.ipaddresses)
    raise EntityOwnershipMismatch(
        f"Host {host.name} has multiple IPs, cannot determine which one to use: {ips}."
    )


@command_registry.register_command(
    prog="assoc",
    description=(
        "Associate MAC address with a host. If the host has multiple A/AAAA "
        "records an IP must be given instead of name."
    ),
    short_desc="Add MAC address to host.",
    flags=[
        Flag("name", "Name or IP of target host.", metavar="NAME/IP"),
        Flag("mac", "Mac address.", metavar="MACADDRESS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def assoc(args: argparse.Namespace) -> None:
    """Associate MAC address with host.

    If the host has multiple A/AAAA records an IP must be given instead of a name.

    :param args: argparse.Namespace (name, mac, force)
    """
    name: str = args.name
    mac: str = args.mac
    force: bool = args.force

    client = get_client()

    # Validate and check if mac is in use
    mac = MacAddress.parse_or_raise(mac)
    ensure_macaddress_associable(mac, force, client)

    # Parse Name as an IP address first, if not found, resolve as a host name
    ipaddress = ipaddress_from_ip_arg(name, client)
    if not ipaddress:
        host = client.resolve_host(name)
        ipaddress = get_associable_ip(host, client)

    client.ipaddress.associate_mac(ipaddress, mac, force=force)
    OutputManager().add_ok(f"Associated mac address {mac} with ip {ipaddress.ipaddress}")


@command_registry.register_command(
    prog="disassoc",
    description=(
        "Disassociate MAC address with a host or ip. If the host has multiple "
        "A/AAAA records an IP must be given instead of a name."
    ),
    short_desc="Disassociate MAC address.",
    flags=[
        Flag("name", description="Name or IP of host.", metavar="NAME/IP"),
    ],
)
def disassoc(args: argparse.Namespace) -> None:
    """Disassociate MAC address with host/ip.

    If the host has multiple A/AAAA records an IP must be given instead of a name.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name

    client = get_client()

    ipaddress = ipaddress_from_ip_arg(name, client)

    # Name is not an IP -> resolve as host
    if not ipaddress:
        host = client.resolve_host(name)
        # Check if name itself looks like a MAC address and find the matching IP.
        # This replicates the old host.has_ip_with_mac(mac) logic.
        if mac := MacAddress.parse(name):
            ipaddress = host.get_ip_by_mac(mac)

        if not ipaddress:
            ips_with_mac = host.ips_with_macaddresses()

            if not ips_with_mac:
                raise InputFailure(
                    f"Host {host.name} does not have any IP addresses with MAC addresses."
                ) from None

            if len(ips_with_mac) > 1:
                raise InputFailure(
                    f"Host {host.name} has multiple IP addresses with MAC addresses."
                ) from None

            ipaddress = ips_with_mac[0]

    client.ipaddress.disassociate_mac(ipaddress)
    OutputManager().add_ok(
        f"Disassociated mac address {ipaddress.macaddress} from ip {ipaddress.ipaddress}"
    )
