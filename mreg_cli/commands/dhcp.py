"""DHCP commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_api.models import IPAddress, NetworkOrIP
from mreg_api.models.fields import MacAddress

from mreg_cli.client import get_client
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import EntityOwnershipMismatch, InputFailure
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.resolution import resolve_host

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

    client = get_client()
    ipobjs = client.ipaddress.list_by_ip(str(addr))
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

    client = get_client()

    mac = MacAddress.parse_or_raise(mac)

    ipaddress = ipaddress_from_ip_arg(name)
    if not ipaddress:
        host = resolve_host(client, name)
        # Find an IP without a MAC address to associate with.
        # This replicates the old host.get_associatable_ip() logic.
        ips_without_mac = [ip for ip in host.ipaddresses if ip.macaddress is None]
        if not ips_without_mac:
            raise InputFailure(
                f"Host {host.name} has no IP addresses available for MAC association."
            )
        if len(ips_without_mac) > 1:
            raise InputFailure(
                f"Host {host.name} has multiple IP addresses without a MAC address. "
                "Specify an IP address instead of a hostname."
            )
        ipaddress = ips_without_mac[0]

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

    ipaddress = ipaddress_from_ip_arg(name)
    if not ipaddress:
        host = resolve_host(client, name)
        # Check if name itself looks like a MAC address and find the matching IP.
        # This replicates the old host.has_ip_with_mac(mac) logic.
        if mac := MacAddress.parse(name):
            matching = [ip for ip in host.ipaddresses if ip.macaddress == mac]
            ipaddress = matching[0] if matching else None

        if not ipaddress:
            # Replicates host.ips_with_macaddresses()
            ips_with_mac = [ip for ip in host.ipaddresses if ip.macaddress is not None]

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
