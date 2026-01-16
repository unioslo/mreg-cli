"""Network output functions."""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING, Any, Sequence

from mreg_cli.choices import CommunitySortOrder
from mreg_cli.output.base import output_timestamps
from mreg_cli.outputmanager import OutputManager

if TYPE_CHECKING:
    import mreg_api.models

    from mreg_cli.api.models import NetworkOrIP


# -----------------------------------------------------------------------------
# Network output functions
# -----------------------------------------------------------------------------


def output_network(network: mreg_api.models.Network, padding: int = 25) -> None:
    """Output a single network.

    :param network: Network to output.
    :param padding: Number of spaces for left-padding the labels.
    """
    # Import here to avoid circular imports
    from mreg_cli.api.models import NetworkOrIP

    manager = OutputManager()

    def fmt(label: str, value: Any) -> None:
        manager.add_line(f"{label:<{padding}}{value}")

    ipnet = NetworkOrIP.parse_or_raise(network.network, mode="network")
    reserved_ips = network.get_reserved_ips()
    # Remove network address and broadcast address from reserved IPs
    reserved_ips_filtered = [
        ip for ip in reserved_ips if ip not in (ipnet.network_address, ipnet.broadcast_address)
    ]

    community_list: list[str] = []
    for community in network.communities:
        host_count = len(community.hosts)
        global_name = f" ({community.global_name})" if community.global_name else ""
        community_list.append(f"{community.name}{global_name} [{host_count}]")

    fmt("Network:", network.network)
    fmt("Netmask:", ipnet.netmask)
    fmt("Description:", network.description)
    fmt("Category:", network.category)
    fmt("Network policy: ", network.policy.name if network.policy else "")
    fmt("Communities:", ", ".join(sorted(community_list)))
    if network.max_communities is not None:
        fmt("Max communities:", network.max_communities)
    fmt("Location:", network.location)
    fmt("VLAN:", network.vlan)
    fmt("DNS delegated:", str(network.dns_delegated))
    fmt("Frozen:", network.frozen)
    fmt("IP-range:", f"{ipnet.network_address} - {ipnet.broadcast_address}")
    fmt("Reserved host addresses:", network.reserved)
    fmt("", f"{ipnet.network_address} (net)")
    for ip in reserved_ips_filtered:
        fmt("", ip)
    if ipnet.broadcast_address in reserved_ips:
        fmt("", f"{ipnet.broadcast_address} (broadcast)")
    if network.excluded_ranges:
        excluded_ips = 0
        for ex_range in network.excluded_ranges:
            excluded_ips += ex_range.excluded_ips()
        fmt("Excluded ranges:", f"{excluded_ips} ipaddresses")
        output_excluded_ranges(network.excluded_ranges, padding=padding)
    fmt("Used addresses:", network.get_used_count())
    fmt("Unused addresses:", f"{network.get_unused_count()} (excluding reserved adr.)")


def output_networks(
    networks: Sequence[mreg_api.models.Network],
    padding: int = 25,
) -> None:
    """Output multiple networks.

    :param networks: List of networks to output.
    :param padding: Number of spaces for left-padding the labels.
    """
    for i, network in enumerate(networks, start=1):
        output_network(network, padding=padding)
        if i != len(networks):  # add newline between networks (except last one)
            OutputManager().add_line("")


def output_unused_addresses(network: mreg_api.models.Network, padding: int = 25) -> None:
    """Output the unused addresses of a network.

    :param network: Network whose unused addresses to output.
    :param padding: Number of spaces for left-padding the output.
    """
    unused = network.get_unused_list()

    manager = OutputManager()
    if not unused:
        manager.add_line(f"No free addresses remaining on network {network.network}")
        return

    for ip in unused:
        manager.add_line(f"{str(ip):<{padding}}")


def output_used_addresses(network: mreg_api.models.Network, padding: int = 46) -> None:
    """Output the used addresses and their corresponding hosts.

    :param network: Network whose used addresses to output.
    :param padding: Width for the IP address column (46 for IPv6 max length).
    """
    used = network.get_used_host_list()
    ptr_overrides = network.get_ptroverride_host_list()
    ips = set(list(used.keys()) + list(ptr_overrides.keys()))
    ips_sorted = sorted(ips, key=ipaddress.ip_address)

    manager = OutputManager()
    if not ips_sorted:
        manager.add_line(f"No used addresses on network {network.network}")
        return

    for ip in ips_sorted:
        if ip in ptr_overrides:
            manager.add_line(f"{ip:<{padding}}{ptr_overrides[ip]} (PTR override)")
        elif ip in used:
            hosts = used[ip]
            msg = f"{ip:<{padding}}{', '.join(hosts)}"
            if len(hosts) > 1:
                msg += " (NO ptr override!!)"
            manager.add_line(msg)


def output_excluded_ranges(
    excluded_ranges: Sequence[mreg_api.models.ExcludedRange],
    padding: int = 32,
) -> None:
    """Output the excluded ranges of a network.

    :param excluded_ranges: List of excluded ranges to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()
    if not excluded_ranges:
        return

    for exrange in excluded_ranges:
        manager.add_line(f" {str(exrange.start_ip):<{padding}} -> {exrange.end_ip}")


# -----------------------------------------------------------------------------
# Community output functions
# -----------------------------------------------------------------------------


def output_community(
    community: mreg_api.models.Community,
    padding: int = 14,
    show_hosts: bool = True,
) -> None:
    """Output a single community.

    :param community: Community to output.
    :param padding: Number of spaces for left-padding the labels.
    :param show_hosts: If True, show list of hosts; otherwise show count only.
    """
    manager = OutputManager()
    manager.add_line(f"{'Name:':<{padding}}{community.name}")
    manager.add_line(f"{'Description:':<{padding}}{community.description}")
    if community.global_name:
        manager.add_line(f"{'Global name:':<{padding}}{community.global_name}")
    output_timestamps(community)

    if show_hosts and community.hosts:
        manager.add_line("Hosts:")
        for host in community.hosts:
            manager.add_line(f"{'':{padding}}{host}")
    else:
        manager.add_line(f"{'Hosts:':<{padding}}{len(community.hosts)}")


def output_communities(
    communities: Sequence[mreg_api.models.Community],
    padding: int = 14,
    show_hosts: bool = True,
    sort: CommunitySortOrder = CommunitySortOrder.NAME,
) -> None:
    """Output multiple communities.

    :param communities: List of communities to output.
    :param padding: Number of spaces for left-padding the labels.
    :param show_hosts: If True, show list of hosts; otherwise show count only.
    :param sort: Sort order for communities.
    """

    def sort_key(community: mreg_api.models.Community) -> Any:
        if sort == CommunitySortOrder.NAME:
            return community.name
        elif sort == CommunitySortOrder.GLOBAL_NAME:
            return community.global_name or ""
        return community.name

    sorted_communities = sorted(communities, key=sort_key)
    for community in sorted_communities:
        output_community(community, padding=padding, show_hosts=show_hosts)
        OutputManager().add_line("")  # add newline between communities


# -----------------------------------------------------------------------------
# Network Policy output functions
# -----------------------------------------------------------------------------


def output_network_policy(policy: mreg_api.models.NetworkPolicy) -> None:
    """Output a network policy.

    :param policy: NetworkPolicy to output.
    """
    manager = OutputManager()
    manager.add_line(f"Name: {policy.name}")
    if policy.description:
        manager.add_line(f"Description: {policy.description}")
    if policy.community_template_pattern:
        manager.add_line(f"Community template pattern: {policy.community_template_pattern}")
    if policy.attributes:
        manager.add_line("Attributes:")
        for attribute in policy.attributes:
            manager.add_line(f" {attribute.name}: {attribute.value}")

    networks = policy.networks()
    if networks:
        manager.add_line("Networks:")
        for network in networks:
            manager.add_line(f" {network.network}")

    output_timestamps(policy)


def output_network_policies(policies: Sequence[mreg_api.models.NetworkPolicy]) -> None:
    """Output multiple network policies.

    :param policies: List of NetworkPolicy objects to output.
    """
    for policy in policies:
        output_network_policy(policy)
        OutputManager().add_line("")  # add newline between policies


def output_network_policy_attributes(
    attributes: Sequence[mreg_api.models.NetworkPolicyAttribute],
    padding: int = 20,
) -> None:
    """Output network policy attributes.

    :param attributes: List of NetworkPolicyAttribute objects to output.
    :param padding: Number of spaces for left-padding the output.
    """
    manager = OutputManager()
    for attr in attributes:
        manager.add_formatted_line(attr.name, f"{attr.description!r}", padding)
