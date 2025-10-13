"""Network commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import (
    Community,
    Host,
    IPAddress,
    Network,
    NetworkOrIP,
    NetworkPolicy,
    NetworkPolicyAttribute,
)
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import (
    DeleteError,
    EntityNotFound,
    ForceMissing,
    InputFailure,
    NetworkOverlap,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, QueryParams
from mreg_cli.utilities.shared import convert_wildcard_to_regex, string_to_int
from mreg_cli.utilities.validators import is_valid_category_tag, is_valid_location_tag

command_registry = CommandRegistry()


class NetworkCommands(BaseCommand):
    """Network commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the network commands."""
        super().__init__(cli, command_registry, "network", "Manage networks.", "Manage networks")


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
        Flag("-policy", description="Policy to apply to network", default=None, metavar="POLICY"),
    ],
)
def create(args: argparse.Namespace) -> None:
    """Create a new network.

    :param args: argparse.Namespace (network, desc, vlan, category, location, frozen)
    """
    network: str = args.network
    desc: str = args.desc
    vlan: str | None = args.vlan
    category: str | None = args.category
    location: str | None = args.location
    frozen: bool = args.frozen
    policy: str | None = args.policy

    if vlan:
        # Validate as int, but still pass str to API
        string_to_int(vlan, "VLAN")
    if category and not is_valid_category_tag(category):
        raise InputFailure("Not a valid category tag")
    if location and not is_valid_location_tag(location):
        raise InputFailure("Not a valid location tag")
    if policy:
        policy_obj = NetworkPolicy.get_by_name_or_raise(policy)
    else:
        policy_obj = None

    arg_network = NetworkOrIP.parse_or_raise(network, mode="network")
    networks = Network.get_list()
    for nw in networks:
        if nw.overlaps(arg_network):
            raise NetworkOverlap(
                f"New network {arg_network} overlaps existing network {nw.network}"
            )

    net = Network.create(
        {
            "network": network,
            "description": desc,
            "vlan": vlan,
            "category": category,
            "location": location,
            "frozen": frozen,
        }
    )
    if net and policy_obj:
        net.set_policy(policy_obj)

    OutputManager().add_ok(f"created network {network}")


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
    networks = [Network.get_by_any_means_or_raise(net) for net in args.networks]
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
            "-host",
            short_desc="Host name",
            metavar="HOST",
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
        addr = NetworkOrIP.parse_or_raise(ip_arg, mode="ip")
        networks = [Network.get_by_ip_or_raise(addr)]
    elif host_arg := args_dict.get("host"):
        host = Host.get_by_any_means_or_raise(host_arg)
        ipaddrs = IPAddress.get_list_by_field("host", host.id)
        networks: list[Network] = []
        for ipaddr in ipaddrs:
            # Get the network for each IP address
            # IP might not be in a network managed by MREG, does not raise exception.
            net = Network.get_by_ip(ipaddr.ipaddress)
            if net and net not in networks:
                networks.append(net)
    else:
        params: QueryParams = {}
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
            raise InputFailure("Need at least one search criteria")

        networks = Network.get_by_query(params)

    if not networks:
        raise EntityNotFound("No networks matching the query were found.")

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
    net = Network.get_by_any_means_or_raise(args.network)
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
    net = Network.get_by_any_means_or_raise(args.network)
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
        OutputManager().add_ok(f"Removed network {args.network}")
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
    net = Network.get_by_any_means_or_raise(args.network)
    net.add_excluded_range(args.start_ip, args.end_ip)
    OutputManager().add_ok(f"Added exclude range to {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.remove_excluded_range(args.start_ip, args.end_ip)
    OutputManager().add_ok(f"Removed exclude range from {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_category(args.category)
    OutputManager().add_ok(f"Updated category tag to {args.category!r} for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_description(args.description)
    OutputManager().add_ok(f"Updated description to {args.description!r} for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_dns_delegation(True)
    OutputManager().add_ok(f"Set DNS delegation to 'True' for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_frozen(True)
    OutputManager().add_ok(f"Updated frozen to 'True' for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_location(args.location)
    OutputManager().add_ok(f"Updated location tag to '{args.location}' for {args.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_reserved(args.number)
    OutputManager().add_ok(f"Updated reserved to '{args.number}' for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_vlan(args.vlan)
    OutputManager().add_ok(f"Updated vlan to {args.vlan} for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_dns_delegation(False)
    OutputManager().add_ok(f"Set DNS delegation to 'False' for {net.network}")


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
    net = Network.get_by_any_means_or_raise(args.network)
    net.set_frozen(False)
    OutputManager().add_ok(f"Updated frozen to 'False' for {net.network}")


##########################################
#           POLICY COMMANDS              #
##########################################


# TODO[rename]: network policy add
@command_registry.register_command(
    prog="policy_add",
    description="Add a policy to a network",
    short_desc="Add a policy to a network",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("policy", description="Policy name", metavar="POLICY"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def policy_add(args: argparse.Namespace) -> None:
    """Add a policy to a network.

    :param args: argparse.Namespace (name, network, force)
    """
    policy: str = args.policy
    network: str = args.network
    force: bool = args.force

    pol = NetworkPolicy.get_by_name_or_raise(policy)
    net = Network.get_by_network_or_raise(network)

    if net.policy and net.policy.id == pol.id:
        raise InputFailure(f"Network {net.network} already has policy {pol.name!r}.")

    # Switching policy requires force
    if net.policy and not force:
        raise ForceMissing(
            f"Network {net.network} already has the policy {net.policy.name!r}. Must force."
        )

    net.set_policy(pol)
    OutputManager().add_ok(f"Added network policy {pol.name!r} to {network}")


# TODO[rename]: network policy create
@command_registry.register_command(
    prog="policy_create",
    description="Create a network policy. Separate attributes with spaces.",
    short_desc="Create a network policy",
    flags=[
        Flag("name", description="Name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
        Flag(
            "-attribute",
            description="Policy attribute(s). Can be specified multiple times.",
            metavar="ATTRIBUTE",
            action="append",
            default=[],
        ),
        Flag(
            "-prefix",
            description="Custom prefix for community names when mapped to global names.",
            default=None,
            metavar="PREFIX",
        ),
    ],
)
def policy_create(args: argparse.Namespace) -> None:
    """Create a network policy.

    :param args: argparse.Namespace (name, description, attributes)
    """
    name: str = args.name
    description: str = args.description
    attribute: list[str] = args.attribute or []
    prefix: str | None = args.prefix

    NetworkPolicy.get_by_name_and_raise(name)

    attrs: list[NetworkPolicyAttribute] = []
    for attr in attribute:
        attrs.append(NetworkPolicyAttribute.get_by_name_or_raise(attr))

    NetworkPolicy.create(
        {
            "name": name,
            "description": description,
            "attributes": [{"name": attr.name, "value": True} for attr in attrs],
            "community_mapping_prefix": prefix,
        }
    )
    OutputManager().add_ok(f"Created network policy {name!r}")


# TODO[rename]: network policy delete
@command_registry.register_command(
    prog="policy_delete",
    description="Delete a network policy",
    short_desc="Delete a network policy",
    flags=[
        Flag("name", description="Policy name", metavar="NAME"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def policy_delete(args: argparse.Namespace) -> None:
    """Delete a network policy.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name
    force: bool = args.force

    pol = NetworkPolicy.get_by_name_or_raise(name)
    networks = Network.get_list_by_field("policy", pol.id)

    if networks and not force:
        nets = ", ".join(f"{net.network!r}" for net in networks)
        raise ForceMissing(
            f"Policy {pol.name!r} is assigned to the following networks: {nets}. Must force."
        )

    pol.delete()
    OutputManager().add_ok(f"Deleted network policy {name!r}")


# TODO[rename]: network policy info
@command_registry.register_command(
    prog="policy_info",
    description="Show information about a network policy",
    short_desc="Show information about a network policy",
    flags=[
        Flag("name", description="Policy name", metavar="NAME"),
    ],
)
def policy_info(args: argparse.Namespace) -> None:
    """Show information about a network policy.

    :param args: argparse.Namespace (name, attributes)
    """
    name: str = args.name

    policy = NetworkPolicy.get_by_name_or_raise(name)
    policy.output()


# TODO[rename]: network policy list
@command_registry.register_command(
    prog="policy_list",
    description="List all or a subset of policies",
    short_desc="List policies",
    flags=[
        Flag(
            "name",
            description="Policy name, or part of name. Can contain wildcards.",
            metavar="FILTER",
            nargs="?",
            default=None,
        ),
    ],
)
def policy_list(args: argparse.Namespace) -> None:
    """List all network policies by given filter.

    :param args: argparse.Namespace (name)
    """
    name: str | None = args.name

    if name:
        policies = NetworkPolicy.get_list_by_name_regex(name)
    else:
        policies = NetworkPolicy.get_list()
    NetworkPolicy.output_multiple(policies)


# TODO[rename]: network policy rename
@command_registry.register_command(
    prog="policy_rename",
    description="Rename a network policy",
    short_desc="Rename a network policy",
    flags=[
        Flag("oldname", description="Old policy name", metavar="OLDNAME"),
        Flag("newname", description="New policy name", metavar="NEWNAME"),
    ],
)
def policy_rename(args: argparse.Namespace) -> None:
    """Rename a network policy.

    :param args: argparse.Namespace (oldname, newname)
    """
    oldname: str = args.oldname
    newname: str = args.newname

    pol = NetworkPolicy.get_by_name_or_raise(oldname)
    pol.rename(newname)
    OutputManager().add_ok(f"Renamed network policy {oldname!r} to {newname!r}")


# TODO[rename]: network policy remove
@command_registry.register_command(
    prog="policy_remove",
    description="Remove a network's policy",
    short_desc="Remove a network's policy",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def policy_remove(args: argparse.Namespace) -> None:
    """Remove a policy from a network.

    :param args: argparse.Namespace (network, force)
    """
    network: str = args.network

    net = Network.get_by_network_or_raise(network)

    if not net.policy:
        raise EntityNotFound(f"Network {net.network} does not have a policy assigned.")

    net.unset_policy()
    OutputManager().add_ok(f"Removed network policy from {network}")


# TODO[rename]: network policy set_description
@command_registry.register_command(
    prog="policy_set_description",
    description="Set a description on a network policy",
    short_desc="Set a description on a network policy",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
        Flag("description", description="New description", metavar="DESCRIPTION"),
    ],
)
def policy_set_description(args: argparse.Namespace) -> None:
    """Set a description on a network policy.

    :param args: argparse.Namespace (name, description)
    """
    policy: str = args.policy
    description: str = args.description

    pol = NetworkPolicy.get_by_name_or_raise(policy)
    pol.patch({"description": description}, validate=False)
    OutputManager().add_ok(f"Set new description for network policy {policy!r}")


# TODO[rename]: network policy set_prefix
@command_registry.register_command(
    prog="policy_set_prefix",
    description="Set the global community mapping prefix for a network policy",
    short_desc="Set community mapping prefix",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
        Flag("prefix", description="New prefix", metavar="PREFIX"),
    ],
)
def policy_set_prefix(args: argparse.Namespace) -> None:
    """Set the global community mapping prefix for a network policy.

    :param args: argparse.Namespace (name, prefix)
    """
    policy: str = args.policy
    prefix: str = args.prefix

    pol = NetworkPolicy.get_by_name_or_raise(policy)
    pol.patch({"community_mapping_prefix": prefix})
    OutputManager().add_ok(f"Set new community mapping prefix for network policy {policy!r}")


# TODO[rename]: network policy set_prefix
@command_registry.register_command(
    prog="policy_unset_prefix",
    description=(
        "Unset the global community mapping prefix for a network polic. "
        "Reverts the prefix to the global default."
    ),
    short_desc="Unset community mapping prefix",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
    ],
)
def policy_unset_prefix(args: argparse.Namespace) -> None:
    """Unset the global community mapping prefix for a network policy.

    :param args: argparse.Namespace (name, prefix)
    """
    policy: str = args.policy

    pol = NetworkPolicy.get_by_name_or_raise(policy)
    pol.patch({"community_mapping_prefix": None})
    OutputManager().add_ok(f"Unset community mapping prefix for network policy {policy!r}")


##########################################
#        POLICY ATTRIBUTE COMMANDS       #
##########################################


# TODO[rename]: network policy attribute create
@command_registry.register_command(
    prog="policy_attribute_add",
    description="Add an attribute to a policy",
    short_desc="Add attribute to policy",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
        Flag("attribute", description="Attribute", metavar="ATTRIBUTE"),
    ],
)
def policy_attribute_add(args: argparse.Namespace) -> None:
    """Add an attribute to a policy.

    :param args: argparse.Namespace (attribute, policy)
    """
    attribute: str = args.attribute
    policy: str = args.policy

    attr = NetworkPolicyAttribute.get_by_name_or_raise(attribute)
    pol = NetworkPolicy.get_by_name_or_raise(policy)

    if pol.get_attribute(attribute):
        raise InputFailure(f"Policy {pol.name!r} already has attribute {attr.name!r}")

    pol.add_attribute(attr, value=True)

    OutputManager().add_ok(f"Added attribute {attr.name!r} to policy {pol.name!r}")


# TODO[rename]: network policy attribute create
@command_registry.register_command(
    prog="policy_attribute_create",
    description="Create a network policy attribute",
    short_desc="Create a network policy attribute",
    flags=[
        Flag("name", description="Name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
    ],
)
def policy_attribute_create(args: argparse.Namespace) -> None:
    """Create a new network policy attribute.

    :param args: argparse.Namespace (name, description)
    """
    name: str = args.name
    description: str = args.description

    NetworkPolicyAttribute.get_by_name_and_raise(name)

    NetworkPolicyAttribute.create({"name": name, "description": description})

    OutputManager().add_ok(f"Created network policy attribute {name!r}")


# TODO[rename]: network policy attribute delete
@command_registry.register_command(
    prog="policy_attribute_delete",
    description="Delete a network policy attribute",
    short_desc="Delete a network policy attribute",
    flags=[
        Flag("attribute", description="attribute", metavar="ATTRIBUTE"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def policy_attribute_delete(args: argparse.Namespace) -> None:
    """Delete a network policy attribute.

    :param args: argparse.Namespace (attribute, force)
    """
    attribute: str = args.attribute
    force: bool = args.force

    attr = NetworkPolicyAttribute.get_by_name_or_raise(attribute)

    if not force and (pols := attr.get_policies()):
        policy_names = ", ".join(f"{pol.name!r}" for pol in pols)
        raise ForceMissing(
            f"Attribute {attr.name!r} is used by the following policies: {policy_names}. Must force."
        )

    OutputManager().add_ok(f"Deleted network policy attribute {attribute!r}")


# TODO[rename]: network policy attribute info
@command_registry.register_command(
    prog="policy_attribute_info",
    description="Show information about a network policy attribute",
    short_desc="Policy attribute info",
    flags=[
        Flag("attribute", description="Attribute", metavar="ATTRIBUTE"),
    ],
)
def policy_attribute_info(args: argparse.Namespace) -> None:
    """Show information about a network policy attribute.

    :param args: argparse.Namespace (attribute)
    """
    attribute: str = args.attribute

    attr = NetworkPolicyAttribute.get_by_name_or_raise(attribute)
    attr.output()


# TODO[rename]: network policy attribute list
@command_registry.register_command(
    prog="policy_attribute_list",
    description="List all network policy attributes",
    short_desc="List network policy attributes",
    flags=[
        Flag(
            "name",
            description="Attribute name, or part of name. Supports wildcards.",
            metavar="FILTER",
            nargs="?",
            default=None,
        )
    ],
)
def policy_attribute_list(args: argparse.Namespace) -> None:
    """List all network policy attributes.

    :param args: argparse.Namespace (name)
    """
    name: str | None = args.name

    if name:
        attributes = NetworkPolicyAttribute.get_list_by_name_regex(name)
    else:
        attributes = NetworkPolicyAttribute.get_list()

    if attributes:
        NetworkPolicyAttribute.output_multiple(attributes)
    else:
        OutputManager().add_line("No match.")


# TODO[rename]: network policy attribute create
@command_registry.register_command(
    prog="policy_attribute_remove",
    description="Remove an attribute from a policy",
    short_desc="Remove attribute from policy",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
        Flag("attribute", description="Attribute", metavar="ATTRIBUTE"),
    ],
)
def policy_attribute_remove(args: argparse.Namespace) -> None:
    """Remove an attribute from a policy.

    :param args: argparse.Namespace (attribute, policy)
    """
    attribute: str = args.attribute
    policy: str = args.policy

    attr = NetworkPolicyAttribute.get_by_name_or_raise(attribute)
    pol = NetworkPolicy.get_by_name_or_raise(policy)

    if not pol.get_attribute(attribute):
        raise InputFailure(f"Policy {pol.name!r} does not have attribute {attr.name!r}")

    pol.remove_attribute(attribute)

    OutputManager().add_ok(f"Removed attribute {attr.name!r} from policy {pol.name!r}")


@command_registry.register_command(
    prog="policy_attribute_set_description",
    description="Set the description of a network policy attribute",
    short_desc="Set network policy attribute description",
    flags=[
        Flag("attribute", description="Attribute name", metavar="ATTRIBUTE"),
        Flag("description", description="New description", metavar="DESCRIPTION"),
    ],
)
def policy_attribute_set_description(args: argparse.Namespace) -> None:
    """Set the description of a network policy attribute.

    :param args: argparse.Namespace (attribute, description)
    """
    attribute: str = args.attribute
    description: str = args.description

    attr = NetworkPolicyAttribute.get_by_name_or_raise(attribute)
    attr.patch({"description": description})
    OutputManager().add_ok(f"Set new description for network policy attribute {attribute!r}")


##########################################
#           COMMUNITY COMMANDS           #
##########################################


# TODO[rename]: network community create
@command_registry.register_command(
    prog="community_create",
    description="Create a network community",
    short_desc="Create a network community",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("name", description="Community name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
    ],
)
def community_create(args: argparse.Namespace) -> None:
    """Create a community.

    :param args: argparse.Namespace (name, description)
    """
    network: str = args.network
    name: str = args.name
    description: str = args.description

    net = Network.get_by_network_or_raise(network)
    com = net.get_community(name)
    if com:
        raise InputFailure(f"Community {name!r} already exists for network {network}")
    net.create_community(name, description)
    OutputManager().add_ok(f"Created community {name!r} for network {network}")


# TODO[rename]: network community delete
@command_registry.register_command(
    prog="community_delete",
    description="Delete a community",
    short_desc="Delete a community",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("community", description="Community name", metavar="COMMUNITY"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def community_delete(args: argparse.Namespace) -> None:
    """Delete a community.

    :param args: argparse.Namespace (network, community, force)
    """
    network: str = args.network
    community: str = args.community
    force: bool = args.force

    net = Network.get_by_network_or_raise(network)
    com = net.get_community_or_raise(community)

    if not force and com.get_hosts():
        raise ForceMissing(f"Community {com.name!r} has hosts. Must force.")

    com.delete()
    OutputManager().add_ok(f"Deleted community {community!r}")


# TODO[rename]: network community info
@command_registry.register_command(
    prog="community_info",
    description="Show detailed information about a community",
    short_desc="Show community info",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("community", description="Community name", metavar="COMMUNITY"),
    ],
)
def community_info(args: argparse.Namespace) -> None:
    """Show detailed information about a community.

    :param args: argparse.Namespace (network, community)
    """
    network: str = args.network
    community: str = args.community

    net = Network.get_by_network_or_raise(network)
    com = net.get_community_or_raise(community)

    com.output()


# TODO[rename]: network community list
@command_registry.register_command(
    prog="community_list",
    description="List all communities in a network",
    short_desc="List communities",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("-hosts", action="store_true", description="Show names of hosts."),
    ],
)
def community_list(args: argparse.Namespace) -> None:
    """List all communities in a network.

    :param args: argparse.Namespace (network, hosts)
    """
    network: str = args.network
    hosts: bool = args.hosts

    net = Network.get_by_network_or_raise(network)
    Community.output_multiple(net.communities, show_hosts=hosts)


# TODO[rename]: network community rename
@command_registry.register_command(
    prog="community_rename",
    description="Rename a community",
    short_desc="Rename a community",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("oldname", description="Old name of community", metavar="OLDNAME"),
        Flag("newname", description="New name of community", metavar="NEWNAME"),
    ],
)
def community_rename(args: argparse.Namespace) -> None:
    """Rename a community.

    :param args: argparse.Namespace (network, oldname, newname)
    """
    network: str = args.network
    oldname: str = args.oldname
    newname: str = args.newname

    net = Network.get_by_network_or_raise(network)
    community = net.get_community_or_raise(oldname)
    community.patch(({"name": newname}))
    OutputManager().add_ok(f"Renamed community {oldname!r} to {newname!r}")


# TODO[rename]: network community set_description
@command_registry.register_command(
    prog="community_set_description",
    description="Set description for a community",
    short_desc="Set community description",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("community", description="Name of community", metavar="COMMUNITY"),
        Flag("description", description="New description", metavar="DESCRIPTION"),
    ],
)
def community_set_description(args: argparse.Namespace) -> None:
    """Set description for a network community.

    :param args: argparse.Namespace (network, community, description)
    """
    network: str = args.network
    community: str = args.community
    description: str = args.description

    net = Network.get_by_network_or_raise(network)
    com = net.get_community_or_raise(community)
    com.patch({"description": description})
    OutputManager().add_ok(f"Set new description for community {community!r}")


def _check_host_ip(host: Host, ip: str | None) -> IPAddress:
    """Ensure host has an IP that can be added to/removed from a community."""
    if not host.ipaddresses:
        raise EntityNotFound(f"Host {host.name!r} is not associated with any networks.")
    elif not ip and len(host.ipaddresses) > 1:
        raise InputFailure(
            f"Host {host.name!r} is associated with multiple IP addresses. Must specify IP."
        )

    if ip:
        ip_t = NetworkOrIP.parse_or_raise(ip, mode="ip")
        ipaddr = host.get_ip(ip_t)
        if not ipaddr:
            raise EntityNotFound(f"Host {host.name!r} is not associated with IP {ip_t}")
    else:
        ipaddr = host.ipaddresses[0]

    return ipaddr


@command_registry.register_command(
    prog="community_host_add",
    description="Add host to a community",
    short_desc="Add host to a community",
    flags=[
        Flag("host", description="Host to add", metavar="HOST"),
        Flag("community", description="Community to add host to", metavar="COMMUNITY"),
        Flag("-ip", description="Specific IP address to associate with community", metavar="IP"),
    ],
)
def community_host_add(args: argparse.Namespace) -> None:
    """Add a host to a community.

    :param args: argparse.Namespace (host, community, network)
    """
    host: str = args.host
    community: str = args.community
    ip: str | None = args.ip

    h = Host.get_by_any_means_or_raise(host)
    ipaddr = _check_host_ip(h, ip)

    if not (net := ipaddr.network()):
        raise EntityNotFound(f"{h.name!r} is not in a network controlled by MREG.")

    com = net.get_community_or_raise(community)

    com.add_host(h, ipaddress=ipaddr.ipaddress)

    OutputManager().add_ok(f"Added host {h.name!r} to community {com.name!r}")


@command_registry.register_command(
    prog="community_host_remove",
    description="Remove host from a community",
    short_desc="Remove host from a community",
    flags=[
        Flag("host", description="Host to remove", metavar="HOST"),
        Flag("community", description="Community to remove host from", metavar="COMMUNITY"),
        Flag("-ip", description="IP address to remove from community", metavar="IP"),
    ],
)
def community_host_remove(args: argparse.Namespace) -> None:
    """Remove a host from a community.

    :param args: argparse.Namespace (network, community, host)
    """
    host: str = args.host
    community: str = args.community
    ip: str | None = args.ip

    h = Host.get_by_any_means_or_raise(host)
    ipaddr = _check_host_ip(h, ip)
    com = h.get_community_or_raise(community, ipaddr)
    com.remove_host(h, ipaddr.ipaddress)

    OutputManager().add_ok(
        f"Removed host {h.name!r} (IP: {ipaddr.ipaddress}) from community {com.name!r}"
    )
