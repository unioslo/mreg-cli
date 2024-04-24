"""DHCP commands for mreg_cli."""
from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.log import cli_info
from mreg_cli.types import Flag
from mreg_cli.utilities.api import patch
from mreg_cli.utilities.host import assoc_mac_to_ip, get_unique_ip_by_name_or_ip

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
    ip = get_unique_ip_by_name_or_ip(args.name)
    new_mac = assoc_mac_to_ip(args.mac, ip, force=args.force)

    if new_mac is not None:
        cli_info(
            "associated mac address {} with ip {}".format(new_mac, ip["ipaddress"]),
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
    ip = get_unique_ip_by_name_or_ip(args.name)

    if ip.get("macaddress"):
        # Update ipaddress
        path = f"/api/v1/ipaddresses/{ip['id']}"
        patch(path, macaddress="")
        cli_info(
            "disassociated mac address {} from ip {}".format(ip["macaddress"], ip["ipaddress"]),
            print_msg=True,
        )
    else:
        cli_info(
            "ipaddress {} has no associated mac address".format(ip["ipaddress"]),
            print_msg=True,
        )
