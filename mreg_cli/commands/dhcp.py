"""DHCP commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import Host, IPAddress
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import InputFailure
from mreg_cli.log import cli_info
from mreg_cli.types import Flag

command_registry = CommandRegistry()


class DHCPCommands(BaseCommand):
    """DHCP commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the DHCP commands."""
        super().__init__(cli, command_registry, "dhcp", "Manage DHCP associations.", "Manage DHCP")


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
    ipaddress_to_use = None

    in_use = IPAddress.get_by_mac(args.mac)
    if in_use:
        raise InputFailure(f"MAC {args.mac} is already in use by {in_use.ip()}.")

    ipobjs = IPAddress.get_by_ip(args.name)
    if ipobjs:
        if len(ipobjs) > 1:
            raise InputFailure(f"IP {args.name} is in use by {len(ipobjs)} hosts.")

        ipaddress_to_use = ipobjs[0]

    if not ipaddress_to_use:
        host = Host.get_by_any_means_or_raise(args.name)
        ipaddress_to_use = host.get_associatable_ip()

    ipaddress_to_use.associate_mac(args.mac, force=args.force)
    cli_info(
        f"Associated mac address {args.mac} with ip {ipaddress_to_use.ip()}",
        print_msg=True,
    )


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
    ipaddress_to_use = None
    ipobjs = IPAddress.get_by_ip(args.name)
    if ipobjs:
        if len(ipobjs) > 1:
            raise InputFailure(f"IP {args.name} is in use by {len(ipobjs)} hosts.")

        ipaddress_to_use = ipobjs[0]

        if not ipaddress_to_use.macaddress:
            raise InputFailure(f"IP {args.name} does not have a MAC address associated.")

    if not ipaddress_to_use:
        host = Host.get_by_any_means_or_raise(args.name)

        try:
            ipaddress_to_use = host.has_ip_with_mac(args.name)
        except ValueError:
            pass

        if not ipaddress_to_use:
            ips_with_mac = host.ips_with_macaddresses()

            if not ips_with_mac:
                raise InputFailure(
                    f"Host {host} does not have any IP addresses with MAC addresses."
                )

            if len(ips_with_mac) > 1:
                raise InputFailure(f"Host {host} has multiple IP addresses with MAC addresses.")

            ipaddress_to_use = ips_with_mac[0]

    mac = ipaddress_to_use.macaddress
    ipaddress_to_use.disassociate_mac()
    cli_info(
        f"Disassociated mac address {mac} from ip {ipaddress_to_use.ip()}",
        print_msg=True,
    )
