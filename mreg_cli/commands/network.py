"""Network commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import (
    Community,
    Host,
    Network,
    NetworkOrIP,
    NetworkPolicy,
    NetworkPolicyAttribute,
)
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import (
    CreateError,
    DeleteError,
    EntityNotFound,
    ForceMissing,
    InputFailure,
    NetworkOverlap,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, JsonMapping, QueryParams
from mreg_cli.utilities.shared import args_to_mapping, convert_wildcard_to_regex, string_to_int
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

    arg_network = NetworkOrIP.parse_or_raise(args.network, mode="network")
    networks = Network.get_list()
    for network in networks:
        if network.overlaps(arg_network):
            raise NetworkOverlap(
                f"New network {arg_network} overlaps existing network {network.network}"
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

    OutputManager().add_ok(f"created network {args.network}")


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
    OutputManager().add_ok(f"Set DNS delegation to 'True' for {net.network!r}")


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
    OutputManager().add_ok(f"Set DNS delegation to 'False' for {net.network!r}")


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


# TODO[rename]: network policy create
@command_registry.register_command(
    prog="policy_create",
    description="Create a network policy",
    short_desc="Create a network policy",
    flags=[
        Flag("name", description="Policy name", metavar="NAME"),
        Flag("attributes", description="Policy Attributes", metavar="ATTRIBUTES", nargs="+"),
    ],
)
def policy_create(args: argparse.Namespace) -> None:
    """Create a network policy.

    :param args: argparse.Namespace (name, attributes)
    """
    name: str = args.name
    attributes: list[str] = args.attributes

    policy_attributes = [NetworkPolicyAttribute.get_by_name_or_raise(a) for a in attributes]
    NetworkPolicy.create(
        {
            "name": name,
            "attributes": [{"attribute": a.id, "value": True} for a in policy_attributes],
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

    policy = NetworkPolicy.get_by_name_or_raise(name)
    for community in policy.communities:
        if community.hosts and not force:
            raise ForceMissing(
                f"Cannot delete policy {name!r}. Its community {community.name!r} has hosts. Must force."
            )

    policy.delete()
    OutputManager().add_ok(f"Deleted network policy {name!r}")


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

    policy = NetworkPolicy.get_by_name_or_raise(oldname)
    policy.patch({"name": newname})
    OutputManager().add_ok(f"Renamed network policy {oldname!r} to {newname!r}")


# TODO[rename]: network policy set_description
@command_registry.register_command(
    prog="policy_set_description",
    description="Set a description on a network policy",
    short_desc="Set a description on a network policy",
    flags=[
        Flag("name", description="Name of network policy", metavar="NAME"),
        Flag("description", description="New description", metavar="DESCRIPTION"),
    ],
)
def policy_set_description(args: argparse.Namespace) -> None:
    """Set a description on a network policy.

    :param args: argparse.Namespace (name, description)
    """
    name: str = args.name
    description: str = args.description

    policy = NetworkPolicy.get_by_name_or_raise(name)
    policy.patch({"name": description})
    OutputManager().add_ok(f"Set new description for network policy {name!r}")


# TODO[rename]: network policy assign
@command_registry.register_command(
    prog="policy_assign",
    description="Assign a policy to a network",
    short_desc="Assign a policy to a network",
    flags=[
        Flag("name", description="Name of network policy", metavar="NAME"),
        Flag("network", description="Network to assign to", metavar="NETWORK"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def policy_assign(args: argparse.Namespace) -> None:
    """Assign a policy to a network.

    :param args: argparse.Namespace (name, network)
    """
    name: str = args.name
    network: str = args.network
    force: bool = args.force

    policy = NetworkPolicy.get_by_name_or_raise(name)
    net = Network.get_by_network_or_raise(network)

    if net.policy and not force:
        raise ForceMissing(f"Network {net.network!r} already has a policy assigned. Must force.")

    net.set_policy(policy)
    OutputManager().add_ok(f"Assigned network policy {name!r} to {network}")


# TODO[rename]: network policy community info
@command_registry.register_command(
    prog="policy_community_info",
    description="Show information about a community",
    short_desc="Show information about a community",
    flags=[
        Flag("community", description="Name of community", metavar="COMMUNITY"),
    ],
)
def policy_community_info(args: argparse.Namespace) -> None:
    """Show information about a community.

    :param args: argparse.Namespace (community)
    """
    community: str = args.community

    comm = Community.get_by_name_or_raise(community)
    comm.output()


# TODO[rename]: network policy community list
@command_registry.register_command(
    prog="policy_list_communities",
    description="List all communities in a network policy",
    short_desc="List communities",
    flags=[
        Flag("name", description="Name of policy", metavar="NAME"),
    ],
)
def policy_list_communities(args: argparse.Namespace) -> None:
    """List all communities in a network policy.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name

    policy = NetworkPolicy.get_by_name_or_raise(name)
    if not policy.communities:
        raise EntityNotFound(f"No communities found in policy {name!r}")

    for community in policy.communities:
        OutputManager().add_line(f"Community: {community.name}")


# TODO[rename]: network policy community create
@command_registry.register_command(
    prog="policy_community_create",
    description="Create a community for a policy",
    short_desc="Create a community",
    flags=[
        Flag("policy", description="Name of policy", metavar="POLICY"),
        Flag("name", description="Name of community", metavar="NAME"),
        Flag("description", description="Description of community", metavar="DESCRIPTION"),
    ],
)
def policy_community_create(args: argparse.Namespace) -> None:
    """Create a community for a policy.

    :param args: argparse.Namespace (policy, community)
    """
    policy: str = args.policy
    name: str = args.name
    description: str = args.description

    # Policy should exist, Community should not exist
    pol = NetworkPolicy.get_by_name_or_raise(policy)
    if pol.get_community(name):
        raise CreateError(f"Policy {policy!r} already has the community {name!r}")

    pol.create_community(name, description)
    OutputManager().add_ok(f"Created community {name!r} for policy {policy!r}")


# TODO[rename]: network policy community rename
@command_registry.register_command(
    prog="policy_community_rename",
    description="Rename a community",
    short_desc="Rename a community",
    flags=[
        Flag("oldname", description="Old name of community", metavar="COMMUNITY"),
        Flag("newname", description="New name of community", metavar="COMMUNITY"),
    ],
)
def policy_community_rename(args: argparse.Namespace) -> None:
    """Rename a community.

    :param args: argparse.Namespace (oldname, newname)
    """
    oldname: str = args.oldname
    newname: str = args.newname

    community = Community.get_by_name_or_raise(oldname)
    community.patch({"name": newname})
    OutputManager().add_ok(f"Renamed community {oldname!r} to {newname!r}")


# TODO[rename]: network policy community set_description
@command_registry.register_command(
    prog="policy_community_set_description",
    description="Set description for a community",
    short_desc="Set community description",
    flags=[
        Flag("community", description="Name of community", metavar="COMMUNITY"),
        Flag("description", description="New description", metavar="DESCRIPTION"),
    ],
)
def policy_community_set_description(args: argparse.Namespace) -> None:
    """Set description for a community.

    :param args: argparse.Namespace (community, description)
    """
    community: str = args.community
    description: str = args.description

    comm = Community.get_by_name_or_raise(community)
    comm.patch({"description": description})
    OutputManager().add_ok(f"Set new description for community {community!r}")


# TODO[rename]: network policy community delete
@command_registry.register_command(
    prog="policy_community_delete",
    description="Delete a community",
    short_desc="Delete a community",
    flags=[
        Flag("community", description="Name of community", metavar="COMMUNITY"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def policy_community_delete(args: argparse.Namespace) -> None:
    """Delete a community.

    :param args: argparse.Namespace (community, force)
    """
    community: str = args.community
    force: bool = args.force

    comm = Community.get_by_name_or_raise(community)
    if comm.hosts and not force:
        raise ForceMissing(f"Community {community!r} has hosts. Must force.")

    comm.delete()
    OutputManager().add_ok(f"Deleted community {community!r}")


# TODO[rename]: network community add_host
@command_registry.register_command(
    prog="community_add_host",
    description="Add a host to a community",
    short_desc="Add a host to a community",
    flags=[
        Flag("host", description="Hostname or IP", metavar="NAME"),
        Flag("community", description="Community to add host to", metavar="COMMUNITY"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def community_add_host(args: argparse.Namespace) -> None:
    """Add a host to a community.

    :param args: argparse.Namespace (host, community, force)
    """
    hostname_or_ip: str = args.host
    community: str = args.community
    force: bool = args.force

    comm = Community.get_by_name_or_raise(community)
    host = Host.get_by_any_means_or_raise(hostname_or_ip)

    if not force and host.network_community and host.network_community.id != comm.id:
        raise CreateError(
            f"Host {host.name!r} is already part of community {host.network_community.name!r}. Must force."
        )

    if comm.add_host(host):
        OutputManager().add_ok(f"Added host {host.name!r} to community {comm.name!r}")
    else:
        raise CreateError(f"Failed to add host {host.name!r} to community {comm.name!r}")


# TODO[rename]: network community remove_host
@command_registry.register_command(
    prog="community_remove_host",
    description="Remove a host from a community",
    short_desc="Remove a host from a community",
    flags=[
        Flag("host", description="Hostname or IP", metavar="NAME"),
        Flag("community", description="Community to add host to", metavar="COMMUNITY"),
    ],
)
def community_remove_host(args: argparse.Namespace) -> None:
    """Remove a host from a community.

    :param args: argparse.Namespace (host, community)
    """
    hostname_or_ip: str = args.host
    community: str = args.community

    comm = Community.get_by_name_or_raise(community)
    host = Host.get_by_any_means_or_raise(hostname_or_ip)
    if not host.network_community:
        raise EntityNotFound(f"Host {host.name!r} is not part of any community")
    if host.network_community.id != comm.id:
        raise EntityNotFound(f"Host {host.name!r} is not part of community {comm.name!r}")

    if comm.remove_host(host):
        OutputManager().add_ok(f"Removed host {host.name!r} from community {comm.name!r}")
    else:
        raise DeleteError(f"Failed to remove host {host.name!r} from community {comm.name!r}")


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
    """Create a network policy attribute.

    :param args: argparse.Namespace (name, description)
    """
    name: str = args.name
    description: str = args.description

    NetworkPolicyAttribute.create({"name": name, "description": description})
    OutputManager().add_ok(f"Created network policy attribute {name!r}")


# TODO[rename]: network policy attribute list
@command_registry.register_command(
    prog="policy_attribute_list",
    description="List all network policy attributes",
    short_desc="List network policy attributes",
    flags=[
        Flag(
            "-name",
            description="Name of the attribute",
            metavar="NAME",
        ),
        Flag("-description", description="Description", metavar="RANGE"),
    ],
)
def policy_attribute_list(args: argparse.Namespace) -> None:
    """List all network policy attributes.

    :param args: argparse.Namespace (name, description)
    """
    # TODO: Implement filtering in the API
    params: QueryParams = {}

    for arg, val in args_to_mapping(args).items():
        if val is None:
            continue
        arg, val = convert_wildcard_to_regex(arg, val)
        params[arg] = val

    attributes = NetworkPolicyAttribute.get_by_query(params)
    NetworkPolicyAttribute.output_multiple(attributes)


# TODO[rename]: network policy attribute set_description
@command_registry.register_command(
    prog="policy_attribute_set_description",
    description="Set the description on a network policy attribute",
    short_desc="Set the description on a network policy attribute",
    flags=[
        Flag(
            "name",
            description="Name of the attribute",
            metavar="NAME",
        ),
        Flag("description", description="New description for the attribute", metavar="RANGE"),
    ],
)
def policy_attribute_set_description(args: argparse.Namespace) -> None:
    """Set the description on a network policy attribute.

    :param args: argparse.Namespace (name, description)
    """
    name: str = args.name
    description: str = args.description

    attribute = NetworkPolicyAttribute.get_by_name_or_raise(name)
    attribute.patch({"description": description})


# TODO[rename]: network policy attribute rename
@command_registry.register_command(
    prog="policy_attribute_rename",
    description="Rename a network policy attribute",
    short_desc="Rename a network policy attribute",
    flags=[
        Flag("oldname", description="Old name of the attribute", metavar="NAME"),
        Flag("newname", description="New name of the attribute", metavar="NAME"),
    ],
)
def policy_attribute_rename(args: argparse.Namespace) -> None:
    """Rename a network policy attribute.

    :param args: argparse.Namespace (oldname, newname)
    """
    oldname: str = args.oldname
    newname: str = args.newname

    attribute = NetworkPolicyAttribute.get_by_name_or_raise(oldname)
    attribute.patch({"name": newname})
