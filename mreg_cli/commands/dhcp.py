"""DHCP commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.fields import MacAddress
from mreg_cli.api.models import Host, IPAddress, NetworkOrIP
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import EntityOwnershipMismatch, InputFailure
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

command_registry = CommandRegistry()


class DHCPCommands(BaseCommand):
    """DHCP commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the DHCP commands."""
        super().__init__(cli, command_registry, "dhcp", "Manage DHCP associations.", "Manage DHCP")


def ipaddress_from_ip_arg(arg: str) -> IPAddress | None:
    """Get an IPAddress object from an IP address argument.

    :param arg: IP address argument.

    :returns: IPAddress object if IP is valid and exists, None if IP is invalid.

    :raises InputFailure: If the IP address is valid but does not exist.
    :raises EntityOwnershipMismatch: If the IP address is in use by multiple hosts.
    """
    if not (addr := NetworkOrIP.parse(arg, mode="ip")):
        return None

    ipobjs = IPAddress.get_by_ip(addr)
    if not ipobjs:
        raise InputFailure(f"IP address {arg} does not exist.")
    elif len(ipobjs) > 1:
        raise EntityOwnershipMismatch(f"IP {arg} is in use by {len(ipobjs)} hosts.")
    return ipobjs[0]


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

    mac = MacAddress.parse_or_raise(mac)
    IPAddress.ensure_associable(mac, force=force)

    ipaddress = ipaddress_from_ip_arg(name)
    if not ipaddress:
        host = Host.get_by_any_means_or_raise(name)
        ipaddress = host.get_associatable_ip()

    ipaddress.associate_mac(mac, force=force)
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

    ipaddress = ipaddress_from_ip_arg(name)
    if not ipaddress:
        host = Host.get_by_any_means_or_raise(name)
        if mac := MacAddress.parse(name):
            ipaddress = host.has_ip_with_mac(mac)

        if not ipaddress:
            ips_with_mac = host.ips_with_macaddresses()

            if not ips_with_mac:
                raise InputFailure(
                    f"Host {host} does not have any IP addresses with MAC addresses."
                ) from None

            if len(ips_with_mac) > 1:
                raise InputFailure(
                    f"Host {host} has multiple IP addresses with MAC addresses."
                ) from None

            ipaddress = ips_with_mac[0]

    ipaddress.disassociate_mac()
    OutputManager().add_ok(
        f"Disassociated mac address {ipaddress.macaddress} from ip {ipaddress.ipaddress}"
    )
