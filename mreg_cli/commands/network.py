"""Network commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_api.models import (
    Community,
    Host,
    IPAddress,
    Network,
    NetworkOrIP,
    NetworkPolicyAttributeValue,
)
from typing_extensions import NotRequired, TypedDict

from mreg_cli.choices import CommunitySortOrder
from mreg_cli.client import get_client
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import (
    DeleteError,
    EntityNotFound,
    ForceMissing,
    InputFailure,
    NetworkOverlap,
)
from mreg_cli.output import (
    output_communities,
    output_community,
    output_network_excluded_ranges,
    output_network_policies,
    output_network_policy,
    output_network_policy_attributes,
    output_network_unused_addresses,
    output_network_used_addresses,
    output_networks,
)
from mreg_cli.output.network import output_network_policy_attribute
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, QueryParams
from mreg_cli.utilities.api import strict_limit
from mreg_cli.utilities.resolution import resolve_host, resolve_network
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


class NetworkCreateKwargs(TypedDict, total=False):
    """Keyword arguments for creating a network."""

    network: str
    description: str
    vlan: int | None
    category: NotRequired[str]
    location: NotRequired[str]
    frozen: bool


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
    client = get_client()
    network: str = args.network
    desc: str = args.desc
    vlan_arg: str | None = args.vlan
    category: str | None = args.category
    location: str | None = args.location
    frozen: bool = args.frozen
    policy: str | None = args.policy

    if vlan_arg:
        vlan = string_to_int(vlan_arg, "VLAN")
    else:
        vlan = None

    if category and not is_valid_category_tag(category):
        raise InputFailure(f"Not a valid category tag: {category!r}")
    if location and not is_valid_location_tag(location):
        raise InputFailure(f"Not a valid location tag: {location!r}")
    if policy:
        policy_obj = client.networkpolicy.get_by_name(policy)
    else:
        policy_obj = None

    arg_network = NetworkOrIP.parse_or_raise(network, mode="network")
    networks = client.network.list()
    for nw in networks:
        if nw.overlaps(arg_network):
            raise NetworkOverlap(
                f"New network {arg_network} overlaps existing network {nw.network}"
            )

    kwargs = NetworkCreateKwargs(
        network=network,
        description=desc,
        vlan=vlan,
        frozen=frozen,
    )
    if location is not None:
        kwargs["location"] = location
    if category is not None:
        kwargs["category"] = category

    net = client.network.create(**kwargs)

    # TODO: investigate if we can pass policy directly to create()
    if policy_obj:
        client.network.update(net, policy=policy_obj.id)

    OutputManager().add_ok(f"created network {net.network}")


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
    client = get_client()
    networks = [resolve_network(client, net) for net in args.networks]
    output_networks(networks)


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
    client = get_client()
    addr_only: bool = args.addr_only
    args_dict = vars(args)

    networks: list[Network] = []
    if ip_arg := args_dict.get("ip"):
        addr = NetworkOrIP.parse_or_raise(ip_arg, mode="ip")
        networks = [client.network.get_by_ip(addr)]
    elif host_arg := args_dict.get("host"):
        host = resolve_host(client, host_arg)
        ipaddrs = client.ipaddress.list_by_host(host)
        for ipaddr in ipaddrs:
            # Get the network for each IP address
            # IP might not be in a network managed by MREG, does not raise exception.
            net = client.network.get_by_ip(str(ipaddr.ipaddress), required=False)
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

        with strict_limit(client):
            networks = client.network.list(limit=500, **params)

    if not networks:
        raise EntityNotFound("No networks matching the query were found.")

    if addr_only:
        for network in networks:
            OutputManager().add_line(network.network)
    else:
        output_networks(networks)
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
    client = get_client()
    net = resolve_network(client, args.network)
    output_network_unused_addresses(net)


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
    client = get_client()
    net = resolve_network(client, args.network)
    output_network_used_addresses(net)


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
    client = get_client()
    net = resolve_network(client, args.network)
    if client.network.get_used_count(net):
        raise DeleteError(
            "Network contains addresses that are in use. Remove hosts before deletion"
        )

    if not args.force:
        raise ForceMissing("Must force.")
    client.network.delete(net)
    OutputManager().add_ok(f"Removed network {args.network}")


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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.add_excluded_range(net, args.start_ip, args.end_ip)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.remove_excluded_range(net, args.start_ip, args.end_ip)
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
    client = get_client()
    net = resolve_network(client, args.network)
    output_network_excluded_ranges(net.excluded_ranges)


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
    client = get_client()
    net = resolve_network(client, args.network)
    # TODO: add category validation
    client.network.update(net, category=args.category)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, description=args.description)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, dns_delegated=True)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, frozen=True)
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
    client = get_client()
    net = resolve_network(client, args.network)
    # TODO: add location validation
    client.network.update(net, location=args.location)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, reserved=args.number)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, vlan=args.vlan)
    OutputManager().add_ok(f"Updated vlan to {args.vlan} for {net.network}")


@command_registry.register_command(
    prog="set_max_communities",  # <network> <max_communities>
    description="Set the maximum number of communities for the network",
    short_desc="Set max communities for network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
        Flag(
            "max_communities",
            description="Max communities.",
            flag_type=int,
            metavar="MAX_COMMUNITIES",
        ),
    ],
)
def set_max_communities(args: argparse.Namespace) -> None:
    """Set the maximum number of communities for the network.

    :param args: argparse.Namespace (network, max_communities)
    """
    client = get_client()
    max_coms: int = args.max_communities
    if max_coms < 0:
        raise InputFailure("Number of communities must be a non-negative integer")

    net = resolve_network(client, args.network)

    # Max communities requires a policy
    if not net.policy:
        raise InputFailure(f"Network {net.network} has no policy assigned.")

    # No change
    if net.max_communities is not None and max_coms == net.max_communities:
        raise InputFailure(f"Network {net.network} already has max communities set to {max_coms}.")

    # Cannot set to less than current number of communities
    if len(net.communities) > max_coms:
        raise InputFailure(
            (
                f"Network {net.network} already has {len(net.communities)} communities, "
                f"which is more than the requested max of {max_coms}."
            )
        )
    client.network.update(net, max_communities=max_coms)
    OutputManager().add_ok(f"Set max communities to {max_coms} for {net.network}")


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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, dns_delegated=False)
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
    client = get_client()
    net = resolve_network(client, args.network)
    client.network.update(net, frozen=False)
    OutputManager().add_ok(f"Updated frozen to 'False' for {net.network}")


@command_registry.register_command(
    prog="unset_max_communities",  # <network>
    description=(
        "Unset the maximum number of communities for the network. "
        "Resets the the limit to the global maximum."
    ),
    short_desc="Unset max communities for network",
    flags=[
        Flag("network", description="Network.", metavar="NETWORK"),
    ],
)
def unset_max_communities(args: argparse.Namespace) -> None:
    """Unset the maximum number of communities for the network.

    :param args: argparse.Namespace (network)
    """
    client = get_client()
    net = resolve_network(client, args.network)

    # No change
    if net.max_communities is None:
        raise InputFailure(f"Network {net.network} already has no community limit.")

    client.network.update(net, max_communities=None)
    OutputManager().add_ok(f"Unset max communities for {net.network}")


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
    client = get_client()
    policy: str = args.policy
    network: str = args.network
    force: bool = args.force

    pol = client.networkpolicy.get_by_name(policy)
    net = client.network.get(network)

    if net.policy and net.policy.id == pol.id:
        raise InputFailure(f"Network {net.network} already has policy {pol.name!r}.")

    # Switching policy requires force
    if net.policy and not force:
        raise ForceMissing(
            f"Network {net.network} already has the policy {net.policy.name!r}. Must force."
        )

    client.network.update(net, policy=pol.id)
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
            "-pattern",
            description="Custom template pattern for community names when mapped to global names.",
            default=None,
            metavar="PATTERN",
        ),
    ],
)
def policy_create(args: argparse.Namespace) -> None:
    """Create a network policy.

    :param args: argparse.Namespace (name, description, attributes)
    """
    client = get_client()
    name: str = args.name
    description: str = args.description
    attribute: list[str] = args.attribute or []
    pattern: str | None = args.pattern

    client.networkpolicy.assert_absent(name)

    attrs: list[NetworkPolicyAttributeValue] = []
    for attr_name in attribute:
        attr = client.network.policy.attribute.get_by_name(attr_name)
        attrs.append(NetworkPolicyAttributeValue(name=attr.name, value=True))

    pol = client.network.policy.create(
        name=name,
        description=description,
        attributes=attrs,
        community_template_pattern=pattern,
    )
    OutputManager().add_ok(f"Created network policy {pol.name!r}")


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
    client = get_client()
    name: str = args.name
    force: bool = args.force

    pol = client.network.policy.get_by_name(name)
    networks = client.network.policy.networks(pol)

    if networks and not force:
        nets = ", ".join(f"{net.network!r}" for net in networks)
        raise ForceMissing(
            f"Policy {pol.name!r} is assigned to the following networks: {nets}. Must force."
        )

    client.network.policy.delete(pol)
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
    client = get_client()
    name: str = args.name

    policy = client.network.policy.get_by_name(name)
    output_network_policy(policy)


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
    client = get_client()
    name: str | None = args.name

    if name:
        policies = client.network.policy.list_by_name_regex(name)
    else:
        policies = client.network.policy.list()
    output_network_policies(policies)


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
    client = get_client()
    oldname: str = args.oldname
    newname: str = args.newname

    pol = client.network.policy.get_by_name(oldname)
    client.network.policy.rename(pol, newname)
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
    client = get_client()
    network: str = args.network

    net = client.network.get(network)

    if not net.policy:
        raise EntityNotFound(f"Network {net.network} does not have a policy assigned.")

    client.network.update(net, policy=None)
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
    client = get_client()
    policy: str = args.policy
    description: str = args.description

    pol = client.network.policy.get_by_name(policy)
    client.network.policy.update(pol, description=description)
    OutputManager().add_ok(f"Set new description for network policy {policy!r}")


# TODO[rename]: network policy set_pattern
@command_registry.register_command(
    prog="policy_set_pattern",
    description="Set the global community mapping template pattern for a network policy",
    short_desc="Set community mapping pattern",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
        Flag("pattern", description="New pattern", metavar="PATTERN"),
    ],
)
def policy_set_pattern(args: argparse.Namespace) -> None:
    """Set the global community mapping templatepattern for a network policy.

    :param args: argparse.Namespace (name, pattern)
    """
    client = get_client()
    policy: str = args.policy
    pattern: str = args.pattern

    pol = client.network.policy.get_by_name(policy)
    client.network.policy.update(pol, community_template_pattern=pattern)
    OutputManager().add_ok(
        f"Set new community mapping template pattern for network policy {policy!r}"
    )


# TODO[rename]: network policy unset_pattern
@command_registry.register_command(
    prog="policy_unset_pattern",
    description=(
        "Unset the global community mapping template pattern for a network policy. "
        "Reverts the pattern to the global default."
    ),
    short_desc="Unset community mapping template pattern",
    flags=[
        Flag("policy", description="Policy", metavar="POLICY"),
    ],
)
def policy_unset_pattern(args: argparse.Namespace) -> None:
    """Unset the global community mapping template pattern for a network policy.

    :param args: argparse.Namespace (name, pattern)
    """
    client = get_client()
    policy: str = args.policy

    pol = client.network.policy.get_by_name(policy)
    client.network.policy.update(pol, community_template_pattern=None)
    OutputManager().add_ok(
        f"Unset community mapping template pattern for network policy {policy!r}"
    )


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
    client = get_client()
    attribute: str = args.attribute
    policy: str = args.policy

    attr = client.network.policy.attribute.get_by_name(attribute)
    pol = client.network.policy.get_by_name(policy)

    if pol.get_attribute(attribute):
        raise InputFailure(f"Policy {pol.name!r} already has attribute {attr.name!r}")

    client.network.policy.add_attribute(pol, attr, value=True)

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
    client = get_client()
    name: str = args.name
    description: str = args.description

    client.network.policy.attribute.assert_absent(name)

    pol = client.network.policy.attribute.create(name=name, description=description)

    OutputManager().add_ok(f"Created network policy attribute {pol.name!r}")


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
    client = get_client()
    attribute: str = args.attribute
    force: bool = args.force

    attr = client.network.policy.attribute.get_by_name(attribute)

    if not force and (pols := client.network.policy.attribute.get_policies(attr)):
        policy_names = ", ".join(f"{pol.name!r}" for pol in pols)
        raise ForceMissing(
            f"Attribute {attr.name!r} is used by the following policies: "
            f"{policy_names}. Must force."
        )

    client.network.policy.attribute.delete(attr)
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
    client = get_client()
    attribute: str = args.attribute

    attr = client.network.policy.attribute.get_by_name(attribute)
    output_network_policy_attribute(attr)


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
    client = get_client()
    name: str | None = args.name

    if name:
        attributes = client.network.policy.attribute.list_by_name_regex(name)
    else:
        attributes = client.network.policy.attribute.list()

    if attributes:
        output_network_policy_attributes(attributes)
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
    client = get_client()
    attribute: str = args.attribute
    policy: str = args.policy

    attr = client.network.policy.attribute.get_by_name(attribute)
    pol = client.network.policy.get_by_name(policy)

    if not pol.get_attribute(attribute):
        raise InputFailure(f"Policy {pol.name!r} does not have attribute {attr.name!r}")

    client.network.policy.remove_attribute(pol, attribute)

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
    client = get_client()
    attribute: str = args.attribute
    description: str = args.description

    attr = client.network.policy.attribute.get_by_name(attribute)
    client.network.policy.attribute.update(attr, description=description)
    OutputManager().add_ok(f"Set new description for network policy attribute {attribute!r}")


##########################################
#           COMMUNITY COMMANDS           #
##########################################


def get_network_community(network: Network, community: str) -> Community:
    """Get a community with a given name from a Network object."""
    com = network.get_community(community)
    if not com:
        raise EntityNotFound(
            f"Community {community!r} does not exist for network {network.network}"
        )
    return com


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
    client = get_client()
    network: str = args.network
    name: str = args.name
    description: str = args.description

    net = client.network.get(network)
    com = net.get_community(name)
    if com:
        raise InputFailure(f"Community {name!r} already exists for network {network}")
    com = client.network.community.create(net, name=name, description=description)
    OutputManager().add_ok(f"Created community {com.name!r} for network {network}")


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
    client = get_client()
    network: str = args.network
    community: str = args.community
    force: bool = args.force

    net = client.network.get(network)
    com = get_network_community(net, community)
    if not force and client.network.community.get_hosts(com, net):
        raise ForceMissing(f"Community {com.name!r} has hosts. Must force.")

    client.network.community.delete(com, net)
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
    client = get_client()
    network: str = args.network
    community: str = args.community

    net = client.network.get(network)
    com = get_network_community(net, community)
    output_community(com)


# TODO[rename]: network community list
@command_registry.register_command(
    prog="community_list",
    description="List all communities in a network",
    short_desc="List communities",
    flags=[
        Flag("network", description="Network", metavar="NETWORK"),
        Flag("-hosts", action="store_true", description="Show hosts in each community."),
        Flag(
            "-sort",
            description="Sorting order",
            choices=list(CommunitySortOrder),
            default=CommunitySortOrder.NAME,
            metavar=CommunitySortOrder.metavar(),
        ),
    ],
)
def community_list(args: argparse.Namespace) -> None:
    """List all communities in a network.

    :param args: argparse.Namespace (network, hosts)
    """
    client = get_client()
    network: str = args.network
    hosts: bool = args.hosts
    sort: CommunitySortOrder = CommunitySortOrder(args.sort)

    net = client.network.get(network)
    output_communities(net.communities, show_hosts=hosts, sort=sort)


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
    client = get_client()
    network: str = args.network
    oldname: str = args.oldname
    newname: str = args.newname

    net = client.network.get(network)
    com = client.network.community.get_by_name(oldname, net)
    client.network.community.update(com, net, name=newname)
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
    client = get_client()
    network: str = args.network
    community: str = args.community
    description: str = args.description

    net = client.network.get(network)
    com = client.network.community.get_by_name(community, net)
    client.network.community.update(com, net, description=description)
    OutputManager().add_ok(f"Set new description for community {community!r}")


def _get_host_ip_to_add(host: Host, ip: str | None) -> IPAddress:
    """Get the IP address to add to a community for a host.

    Requires `ip` to be specified if the host has multiple IP addresses.

    :param host: Host object
    :param ip: Optional IP address string
    :return: IPAddress object

    :raises EntityNotFound: If the host has no IP addresses.
    :raises EntityNotFound: If the given IP address is not associated with the host.
    :raises InputFailure: If the host has multiple IP addresses and no IP is specified.
    """
    if not host.ipaddresses:
        raise EntityNotFound(f"Host {host.name!r} is not associated with any networks.")

    if not ip and len(host.ipaddresses) > 1:
        raise InputFailure(
            f"Host {host.name!r} is associated with multiple IP addresses. Must specify IP."
        )

    # Disambiguate or choose the first IP address if only one is present
    if ip:
        ipaddr = _get_host_ip(host, ip)
    else:
        ipaddr = host.ipaddresses[0]

    # NOTE: no check if the IP address is already associated with a community

    return ipaddr


def _get_host_ip(host: Host, ip: str) -> IPAddress:
    """Thin wrapper over Host.get_ip() that raises an exception if the IP address is not found."""
    ip_t = NetworkOrIP.parse_or_raise(ip, mode="ip")
    ipaddr = host.get_ip(ip_t)
    if not ipaddr:
        raise EntityNotFound(f"Host {host.name!r} is not associated with IP {ip_t}")
    return ipaddr


def _get_host_community_and_ip_to_remove(
    host: Host, community: str, ip: str | None
) -> tuple[Community, IPAddress]:
    """Retrieve the Community and IPaddress object for a host given a community name."""
    # NOTE: all this scaffolding presents a very compelling argument for
    # adding server-side functionality for removing a host from a community
    # given a hostname and a community name.

    associations = host.get_community_associations(community)

    # Disambiguate by IP if specified
    if ip:
        ipaddr = _get_host_ip(host, ip)
        associations = [assoc for assoc in associations if assoc[1].id == ipaddr.id]

    # Require a single matching HostCommunity:

    # No matches
    if len(associations) == 0:
        msg = f"Host {host.name!r} is not part of community {community!r}"
        if ip:
            msg += f" on IP {ip}"
        raise EntityNotFound(msg)
    # Too many matches
    elif len(associations) > 1:
        # Try to get the IP address objects associated with the ipaddress IDs
        # of the HostCommunity objects.
        ips_str = ", ".join(str(assoc[1].ipaddress) for assoc in associations)
        raise InputFailure(
            f"Host is part of community {community!r} on multiple IPs ({ips_str}). Must specify IP."
        )
    # Single match
    else:
        return associations[0]


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
    client = get_client()
    host: str = args.host
    community: str = args.community
    ip: str | None = args.ip

    h = resolve_host(client, host)
    ipaddr = _get_host_ip_to_add(h, ip)

    net = client.network.get_by_ip(str(ipaddr.ipaddress), required=False)
    if not net:
        raise EntityNotFound(f"{h.name!r} is not in a network controlled by MREG.")

    com = get_network_community(net, community)
    client.network.community.add_host(com, net, h, ipaddress=ipaddr.ipaddress)

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
    client = get_client()
    host: str = args.host
    community: str = args.community
    ip: str | None = args.ip

    h = resolve_host(client, host)
    com, ipaddr = _get_host_community_and_ip_to_remove(h, community, ip)

    net = client.network.get_by_ip(str(ipaddr.ipaddress), required=False)
    if not net:
        raise EntityNotFound(f"{h.name!r} is not in a network controlled by MREG.")

    client.network.community.remove_host(com, net, h, ipaddress=ipaddr.ipaddress)

    OutputManager().add_ok(
        f"Removed host {h.name!r} (IP: {ipaddr.ipaddress}) from community {com.name!r}"
    )
