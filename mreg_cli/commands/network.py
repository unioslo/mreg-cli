"""Network commands for mreg_cli."""

from __future__ import annotations

import argparse
import ipaddress
import urllib.parse
from typing import Any

from mreg_cli.api.fields import IPAddressField
from mreg_cli.api.models import Network
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import DeleteError, ForceMissing, InputFailure
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get, patch, post
from mreg_cli.utilities.network import (
    get_network,
    get_network_reserved_ips,
    get_network_unused_list,
    get_network_used_list,
    ipsort,
)
from mreg_cli.utilities.shared import convert_wildcard_to_regex, string_to_int
from mreg_cli.utilities.validators import (
    is_valid_category_tag,
    is_valid_ip,
    is_valid_location_tag,
    is_valid_network,
)

command_registry = CommandRegistry()


class NetworkCommands(BaseCommand):
    """Network commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the network commands."""
        super().__init__(cli, command_registry, "network", "Manage networks.", "Manage networks")


def get_network_range_from_input(net: str) -> str:
    """Return network range from input.

    - If input is a valid ip address, return the network range of the ip address.
    - If input is a valid network range, return the input.
    - Otherwise, print a warning and abort.
    """
    if net.endswith("/"):
        net = net[:-1]
    if is_valid_ip(net):
        network = get_network(net)
        if not network:
            cli_error(f"Network not found for ip {net}")
        return network.network
    elif is_valid_network(net):
        return net
    else:
        cli_warning("Not a valid ip or network")


# helper methods
def print_network_unused(count: int, padding: int = 25) -> None:
    """Pretty print amount of unused addresses."""
    OutputManager().add_line(
        "{1:<{0}}{2}{3}".format(padding, "Unused addresses:", count, " (excluding reserved adr.)")
    )


def format_network_excluded_ranges(info: list[dict[str, Any]], padding: int = 25) -> None:
    """Pretty print excluded ranges."""
    if not info:
        return
    count = 0
    for i in info:
        start_ip = ipaddress.ip_address(i["start_ip"])
        end_ip = ipaddress.ip_address(i["end_ip"])
        count += int(end_ip) - int(start_ip) + 1
    manager = OutputManager()
    manager.add_line("{1:<{0}}{2} ipaddresses".format(padding, "Excluded ranges:", count))
    for i in info:
        manager.add_line("{1:<{0}}{2} -> {3}".format(padding, "", i["start_ip"], i["end_ip"]))


def format_network_reserved(ip_range: str, reserved: int, padding: int = 25) -> None:
    """Pretty print ip range and reserved addresses list."""
    network = ipaddress.ip_network(ip_range)
    manager = OutputManager()
    manager.add_line(
        "{1:<{0}}{2} - {3}".format(
            padding, "IP-range:", network.network_address, network.broadcast_address
        )
    )
    manager.add_line("{1:<{0}}{2}".format(padding, "Reserved host addresses:", reserved))
    manager.add_line("{1:<{0}}{2}{3}".format(padding, "", network.network_address, " (net)"))
    res = get_network_reserved_ips(ip_range)
    res.remove(str(network.network_address))
    broadcast = False
    if str(network.broadcast_address) in res:
        res.remove(str(network.broadcast_address))
        broadcast = True
    for host in res:
        manager.add_line("{1:<{0}}{2}".format(padding, "", host))
    if broadcast:
        manager.add_line(
            "{1:<{0}}{2}{3}".format(padding, "", network.broadcast_address, " (broadcast)")
        )


def print_network(info: int | str, text: str, padding: int = 25) -> None:
    """Pretty print network info."""
    OutputManager().add_line("{1:<{0}}{2}".format(padding, text, info))


##########################################
# Implementation of sub command 'create' #
##########################################


@command_registry.register_command(
    prog="create",
    description="Create a new network",
    short_desc="Create a new network",
    flags=[
        Flag("-network", description="Network.", required=True, metavar="NETWORK"),
        Flag(
            "-desc",
            description="Network description.",
            required=True,
            metavar="DESCRIPTION",
        ),
        Flag("-vlan", description="VLAN.", default=None, metavar="VLAN"),
        Flag("-category", description="Category.", default=None, metavar="Category"),
        Flag("-location", description="Location.", default=None, metavar="LOCATION"),
        Flag("-frozen", description="Set frozen network.", action="store_true"),
    ],
)
def create(args: argparse.Namespace) -> None:
    """Create a new network.

    :param args: argparse.Namespace (network, desc, vlan, category, location, frozen)
    """
    if args.vlan:
        string_to_int(args.vlan, "VLAN")
    if args.category and not is_valid_category_tag(args.category):
        raise InputFailure("Not a valid category tag")
    if args.location and not is_valid_location_tag(args.location):
        raise InputFailure("Not a valid location tag")

    arg_network = Network.str_to_network(args.network)
    networks = Network.get_list()
    for network in networks:
        if network.overlaps(arg_network):
            cli_warning(
                "Overlap found between new network {} and existing network {}".format(
                    arg_network, network.network
                )
            )

    Network.create(
        {
            "network": args.network,
            "description": args.desc,
            "vlan": args.vlan,
            "category": args.category,
            "location": args.location,
            "frozen": args.frozen,
        }
    )

    cli_info(f"created network {args.network}", print_msg=True)


@command_registry.register_command(
    prog="info",
    description="Display network info for one or more networks.",
    short_desc="Display network info.",
    flags=[
        Flag(
            "networks",
            description="One or more networks.",
            nargs="+",
            metavar="NETWORK",
        ),
    ],
)
def info(args: argparse.Namespace) -> None:
    """Display network info.

    :param args: argparse.Namespace (networks)
    """
    networks = [Network.get_by_network_or_raise(net) for net in args.networks]
    Network.output_multiple(networks)


@command_registry.register_command(
    prog="find",
    description="Search for networks based on a range of search parameters",
    short_desc="Search for networks",
    flags=[
        Flag(
            "-ip",
            description="Exact IP address",
            metavar="IP",
        ),
        Flag(
            "-network",
            description="Network address",
            metavar="NETWORK",
        ),
        Flag(
            "-description",
            description="Description. Supports * as a wildcard",
            metavar="DESCRIPTION",
        ),
        Flag(
            "-vlan",
            description="VLAN",
            metavar="VLAN",
        ),
        Flag(
            "-dns_delegated",
            description="DNS delegation status (0 or 1)",
            metavar="DNS-DELEGATED",
        ),
        Flag(
            "-category",
            description="Category",
            metavar="CATEGORY",
        ),
        Flag(
            "-location",
            description="Location",
            metavar="LOCATION",
        ),
        Flag(
            "-frozen",
            description="Frozen status (0 or 1)",
            metavar="FROZEN",
        ),
        Flag(
            "-reserved",
            description="Exact number of reserved network addresses",
            metavar="RESERVED",
        ),
        Flag(
            "-addr-only",
            description="Only print network address of matching networks",
            action="store_true",
        ),
        Flag(
            "-limit",
            description="Maximum number of networks to print",
            metavar="LIMIT",
            flag_type=int,
        ),
        Flag(
            "-silent",
            description="Do not print meta info (number of networks found, limit reached, etc.)",
            action="store_true",
        ),
    ],
)
def find(args: argparse.Namespace) -> None:
    """List networks matching search criteria.

    :param args: argparse.Namespace (limit, silent, addr_only, ip, network, description, vlan,
                                     dns_delegated, category, location, frozen, reserved)
    """
    args_dict = vars(args)

    if ip_arg := args_dict.get("ip"):
        addr = IPAddressField(address=ip_arg)
        networks = [Network.get_by_ip_or_raise(addr.address)]
    else:
        params: dict[str, str] = {}
        param_names = [
            "network",
            "description",
            "vlan",
            "dns_delegated",
            "category",
            "location",
            "frozen",
            "reserved",
        ]
        for name in param_names:
            value = args_dict.get(name)
            if value is None:
                continue
            param, val = convert_wildcard_to_regex(name, value)
            params[param] = val

        if not params:
            cli_warning("Need at least one search criteria")

        networks = Network.get_by_query(params)

    if not networks:
        cli_warning("No networks matching the query were found.")

    Network.output_multiple(networks)
    if not args.silent:
        s = "s" if len(networks) > 1 else ""
        OutputManager().add_line(
            f"\nFound {len(networks)} network{s} matching the search criteria."
        )


@command_registry.register_command(
    prog="list_unused_addresses",
    description="Lists all the unused addresses for a network",
    short_desc="Lists unused addresses",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def list_unused_addresses(args: argparse.Namespace) -> None:
    """List all the unused addresses for a network.

    :param args: argparse.Namespace (network)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.output_unused_addresses()


@command_registry.register_command(
    prog="list_used_addresses",
    description="Lists all the used addresses for a network",
    short_desc="Lists all the used addresses for a network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def list_used_addresses(args: argparse.Namespace) -> None:
    """List all the used addresses for a network.

    :param args: argparse.Namespace (network)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.output_used_addresses()


@command_registry.register_command(
    prog="remove",
    description="Remove network",
    short_desc="Remove network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def remove(args: argparse.Namespace) -> None:
    """Remove network.

    :param args: argparse.Namespace (network, force)
    """
    net = Network.get_by_any_means_or_raise(args.network)
    if net.get_used_count():
        raise DeleteError(
            "Network contains addresses that are in use. Remove hosts before deletion"
        )

    if not args.force:
        raise ForceMissing("Must force.")
    if net.delete():
        cli_info(f"Removed network {args.network}", print_msg=True)
    else:
        raise DeleteError(f"Unable to delete network {args.network}")


@command_registry.register_command(
    prog="add_excluded_range",
    description="Add an excluded range to a network",
    short_desc="Add an excluded range to a network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("start_ip", description="Start ipaddress", metavar="STARTIP"),
        Flag("end_ip", description="End ipaddress", metavar="ENDIP"),
    ],
)
def add_excluded_range(args: argparse.Namespace) -> None:
    """Add an excluded range to a network.

    :param args: argparse.Namespace (network, start_ip, end_ip)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.add_excluded_range(args.start_ip, args.end_ip)
    cli_info(f"Added exclude range to {net.network}", True)


@command_registry.register_command(
    prog="remove_excluded_range",
    description="Remove an excluded range to a network",
    short_desc="Remove an excluded range to a network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("start_ip", description="Start ipaddress", metavar="STARTIP"),
        Flag("end_ip", description="End ipaddress", metavar="ENDIP"),
    ],
)
def remove_excluded_range(args: argparse.Namespace) -> None:
    """Remove an excluded range to a network.

    :param args: argparse.Namespace (network, start_ip, end_ip)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.remove_excluded_range(args.start_ip, args.end_ip)
    cli_info(f"Removed exclude range from {net.network}", print_msg=True)


@command_registry.register_command(
    prog="list_excluded_ranges",
    description="List excluded ranges for a network",
    short_desc="List excluded ranges for a network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def list_excluded_ranges(args: argparse.Namespace) -> None:
    """List excluded ranges for a network.

    :param args: argparse.Namespace (network, start_ip, end_ip)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.output_excluded_ranges()


@command_registry.register_command(
    prog="set_category",
    description="Set category tag for network",
    short_desc="Set category tag for network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("category", description="Category tag.", metavar="CATEGORY-TAG"),
    ],
)
def set_category(args: argparse.Namespace) -> None:
    """Set category tag for network.

    :param args: argparse.Namespace (network, category)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_category(args.category)
    cli_info(f"Updated category tag to {args.category!r} for {net.network}", True)


@command_registry.register_command(
    prog="set_description",
    description="Set description for network",
    short_desc="Set description for network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("description", description="Network description.", metavar="DESC"),
    ],
)
def set_description(args: argparse.Namespace) -> None:
    """Set description for network.

    :param args: argparse.Namespace (network, description)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_description(args.description)
    cli_info(f"Updated description to {args.description!r} for {net.network}", True)


@command_registry.register_command(
    prog="set_dns_delegated",
    description="Set that DNS-administration is being handled elsewhere.",
    short_desc="Set that DNS-administration is being handled elsewhere.",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def set_dns_delegated(args: argparse.Namespace) -> None:
    """Set that DNS-administration is being handled elsewhere.

    :param args: argparse.Namespace (network)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_dns_delegation(True)
    cli_info(f"Set DNS delegation to 'True' for {net.network!r}", True)


@command_registry.register_command(
    prog="set_frozen",
    description="Freeze a network.",
    short_desc="Freeze a network.",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def set_frozen(args: argparse.Namespace) -> None:
    """Freeze a network.

    :param args: argparse.Namespace (network)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_frozen(True)
    cli_info(f"Updated frozen to 'True' for {net.network}", print_msg=True)


@command_registry.register_command(
    prog="set_location",
    description="Set location tag for network",
    short_desc="Set location tag for network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("location", description="Location tag.", metavar="LOCATION-TAG"),
    ],
)
def set_location(args: argparse.Namespace) -> None:
    """Set location tag for network.

    :param args: argparse.Namespace (network, location)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_location(args.location)
    cli_info(f"Updated location tag to '{args.location}' for {args.network}", True)


@command_registry.register_command(
    prog="set_reserved",
    description="Set number of reserved hosts.",
    short_desc="Set number of reserved hosts.",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag(
            "number",
            description="Number of reserved hosts.",
            flag_type=int,
            metavar="NUM",
        ),
    ],
)
def set_reserved(args: argparse.Namespace) -> None:
    """Set number of reserved hosts for a network.

    :param args: argparse.Namespace (network, number)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_reserved(args.number)
    cli_info(f"Updated reserved to '{args.number}' for {net.network}", print_msg=True)


@command_registry.register_command(
    prog="set_vlan",  # <network> <vlan>
    description="Set VLAN for network",
    short_desc="Set VLAN for network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag("vlan", description="VLAN.", flag_type=int, metavar="VLAN"),
    ],
)
def set_vlan(args: argparse.Namespace) -> None:
    """Set VLAN for network.

    :param args: argparse.Namespace (network, vlan)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_vlan(args.vlan)
    cli_info(f"Updated vlan to {args.vlan} for {net.network}", print_msg=True)


@command_registry.register_command(
    prog="unset_dns_delegated",
    description="Set that DNS-administration is not being handled elsewhere.",
    short_desc="Set that DNS-administration is not being handled elsewhere.",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def unset_dns_delegated(args: argparse.Namespace) -> None:
    """Set that DNS-administration is not being handled elsewhere.

    :param args: argparse.Namespace (network)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_dns_delegation(False)
    cli_info(f"Set DNS delegation to 'False' for {net.network!r}", True)


@command_registry.register_command(
    prog="unset_frozen",
    description="Unfreeze a network.",
    short_desc="Unfreeze a network.",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def unset_frozen(args: argparse.Namespace) -> None:
    """Unfreeze a network.

    :param args: argparse.Namespace (network)
    """
    net = Network.get_by_network_or_raise(args.network)
    net.set_frozen(False)
    cli_info(f"Updated frozen to 'False' for {net.network}", print_msg=True)
