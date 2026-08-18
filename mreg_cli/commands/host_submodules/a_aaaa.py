"""A/AAAA-related subcommands for the host command.

Commands implemented:
    - a_add
    - a_change
    - a_move
    - a_remove
    - a_show
    - aaaa_add
    - aaaa_change
    - aaaa_move
    - aaaa_remove
    - aaaa_show
"""

from __future__ import annotations

import argparse
from enum import Enum, auto

from mreg_api.models import Host, Network, NetworkOrIP
from mreg_api.models.fields import MacAddress

from mreg_cli.client import get_client
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    EntityAlreadyExists,
    EntityNotFound,
    ForceMissing,
    InputFailure,
)
from mreg_cli.output import output_host_ipaddresses
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, IP_AddressT, IP_Version
from mreg_cli.utilities.resolution import resolve_host


class IPOperation(Enum):
    """Enum for IP operations."""

    ADD = auto()
    CHANGE = auto()
    MOVE = auto()
    REMOVE = auto()


def _bail_if_ip_in_use_and_not_force(ip: IP_AddressT) -> None:
    """Check if an IP is in use and bail if it is.

    :param ip: The IP address to check.
    """
    client = get_client()
    hosts_using_ip = client.host.list_by_ip(str(ip))
    if hosts_using_ip:
        hostnames = ", ".join(str(h.name) for h in hosts_using_ip)
        raise ForceMissing(f"IP {ip} in use by {hostnames}, must force.")


def _bail_if_ip_reserved_and_not_force(ip: IP_AddressT, network: Network | None) -> None:
    """Check if an IP is a network or broadcast address of a network and bail if it is.

    :param ip: The IP address to check.
    :param network: The network the IP belongs to, if any.
    """
    if network and ip == network.broadcast_address:
        raise ForceMissing(
            f"IP {ip} is the broadcast address of network {network.network}, must force"
        )
    if network and ip == network.network_address:
        raise ForceMissing(
            f"IP {ip} is the network address of network {network.network}, must force"
        )


def check_ip_constraints(
    ip: IP_AddressT,
    network: Network | None,
    host: Host,
    operation: IPOperation,
    force: bool,
) -> None:
    """Check if an IP address can be added or changed.

    Runs checks to ensure the IP is not in use or reserved.

    :param ip: The IP address to check.
    :param network: The network the IP belongs to, if any.
    :param host: The host to which the IP is being added or changed.
    :param operation: The operation being performed.
    :param force: Whether to bypass the checks.
    """
    # Bypass checks if in force mode
    if force:
        return

    if not network:
        raise ForceMissing(f"Network for {ip} not found, must force")
    if network and network.frozen:
        raise ForceMissing(f"Network {network.network} is frozen, must force")

    # Check if host already has this IP
    if host.has_ip(ip):
        raise EntityAlreadyExists(f"Host {host} already has IP {ip}")

    if operation == IPOperation.ADD and len(host.ipaddresses) > 0:
        raise ForceMissing(f"Host {host} already has one or more ip addresses, must force")

    _bail_if_ip_reserved_and_not_force(ip, network)
    _bail_if_ip_in_use_and_not_force(ip)


def _ip_change(name: str, old: str, new: str, force: bool, ipversion: IP_Version) -> None:
    """Change A record. If <name> is an alias the cname host is used.

    :param name: Name of the target host.
    :param old: The existing IP that should be changed.
    :param new: The new IP address.
    :param force: Whether to force the change.
    :param ipversion: 4 or 6
    """
    if old == new:
        raise EntityAlreadyExists("New and old IP are equal")

    client = get_client()

    old_ip = NetworkOrIP.parse_or_raise(old, mode="ip")

    new_ip = NetworkOrIP.validate(new)
    network = None
    if new_ip.is_network():
        network = client.network.get(str(new_ip.ip_or_network))
        new_ip = client.network.get_first_available_ip(network)
    else:
        network = client.network.get_by_ip(str(new_ip.as_ip()), required=False)
        new_ip = new_ip.as_ip()

    if old_ip.version != ipversion:
        raise InputFailure("Old IP version does not match the requested version")

    if new_ip.version != ipversion:
        raise InputFailure("New IP version does not match the requested version")

    host = resolve_host(client, name)

    # Find the IPAddress object for the old IP
    host_ip = next(
        (h_ip for h_ip in host.ipaddresses if h_ip.ipaddress == old_ip),
        None,
    )
    if not host_ip:
        raise EntityNotFound(f"Host {host} does not have IP {old_ip}")

    check_ip_constraints(new_ip, network, host, IPOperation.CHANGE, force)

    client.ipaddress.update(host_ip, ipaddress=new_ip)

    OutputManager().add_ok(f"changed ip {old} to {new_ip} for {host}")


def _ip_move(ipaddr: str, fromhost: str, tohost: str, ipversion: IP_Version) -> None:
    """Move an IP from a host to another host. Will move also move the PTR, if any.

    :param ipaddr: IP to move
    :param fromhost: Name of source host
    :param tohost: Name of destination host
    :param ipversion: 4 or 6
    """
    client = get_client()

    ip_addr = NetworkOrIP.parse_or_raise(ipaddr, mode="ip")
    if ip_addr.version != ipversion:
        raise InputFailure(
            f"IP version {ip_addr.version} does not match the requested version {ipversion}"
        )

    from_host = resolve_host(client, fromhost)
    to_host = resolve_host(client, tohost)

    # Find the IPAddress object on from_host
    host_ip = next(
        (h_ip for h_ip in from_host.ipaddresses if h_ip.ipaddress == ip_addr),
        None,
    )

    # Find PTR override on from_host
    ptr = next(
        (p for p in from_host.ptr_overrides if p.ipaddress == ip_addr),
        None,
    )

    if not host_ip and not ptr:
        raise EntityNotFound(f"Host {from_host} has no IP or PTR with address {ipaddr}")

    msg = ""
    if host_ip:
        client.ipaddress.update(host_ip, host=to_host)
        msg = f"Moved ipaddress {ipaddr}"
    else:
        msg += "No ipaddresses matched. "

    if ptr:
        client.ptroverride.update(ptr, host=to_host)
        msg += "Moved PTR override."

    OutputManager().add_line(msg)


def _ip_remove(name: str, ipaddr: str, ipversion: IP_Version, force: bool = False) -> None:
    """Remove A record from host. If <name> is an alias the cname host is used.

    :param name: Name of the target host.
    :param ipaddr: IP to remove.
    :param ipversion: 4 or 6
    """
    client = get_client()

    # TODO: use event suppression ctx manager to avoid printing cname and PTR resolution here
    host = resolve_host(client, name)
    ip_addr = NetworkOrIP.parse_or_raise(ipaddr, mode="ip")
    if ip_addr.version != ipversion:
        raise InputFailure(
            f"IP version {ip_addr.version} does not match the requested version {ipversion}"
        )

    host_ip = next(
        (h_ip for h_ip in host.ipaddresses if h_ip.ipaddress == ip_addr),
        None,
    )
    if not host_ip:
        raise EntityNotFound(f"Host {host} does not have IP {ipaddr}")

    # Check if we fetched the host via a CNAME.
    if not force and host.cnames:
        # Expand the name to a FQDN and check for CNAME
        fqdn_name = client.fqdn(name)
        cname = client.cname.get_by_name(fqdn_name)
        if cname:
            raise ForceMissing(f"{cname.name} is a CNAME for {host.name}, must force.")

    client.ipaddress.delete(host_ip)
    OutputManager().add_ok(f"Removed ipaddress {ipaddr} from {host}")


def _ip_add(
    name: str,
    ipaddr: str,
    macaddress: str | None = None,
    force: bool = False,
    ipversion: IP_Version = 4,
) -> Host:
    """Add a new IP address to a host.

    :param name: Name of the host to add the IP to.
    :param ipaddr: The IP address to add.
    :param macaddress: The MAC address to add.
    :param force: Whether to force the addition.
    :param ipversion: 4 or 6

    :return: The updated host object.
    """
    client = get_client()

    host = resolve_host(client, name)
    ip_or_net = NetworkOrIP.validate(ipaddr)

    if ipversion == 4 and (ip_or_net.is_ipv6() or ip_or_net.is_ipv6_network()):
        raise InputFailure("Use aaaa_add for IPv6 addresses")
    elif ipversion == 6 and (ip_or_net.is_ipv4() or ip_or_net.is_ipv4_network()):
        raise InputFailure("Use a_add for IPv4 addresses")

    ip = None
    network = None
    if ip_or_net.is_network():
        network = client.network.get(str(ip_or_net.ip_or_network))
        ip = client.network.get_first_available_ip(network)
    else:
        network = client.network.get_by_ip(str(ip_or_net.as_ip()), required=False)
        ip = ip_or_net.as_ip()

    check_ip_constraints(ip, network, host, IPOperation.ADD, force)

    mac = None
    if macaddress:
        mac = MacAddress.parse_or_raise(macaddress)

    client.ipaddress.create(host=host, ipaddress=ip, macaddress=mac)
    OutputManager().add_ok(f"Added ipaddress {ip} to {host}")

    # Resolve and return the updated host
    updated_host = resolve_host(client, str(host.name))
    return updated_host


@command_registry.register_command(
    prog="a_add",
    description="Add an A record to host. If NAME is an alias the cname host is used.",
    short_desc="Add A record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag(
            "ip",
            description=(
                "The IP of new A record. May also be a network, "
                "in which case a random IP address from that network "
                "is chosen."
            ),
            metavar="IP/network",
        ),
        Flag("-macaddress", description="Mac address", metavar="MACADDRESS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def a_add(args: argparse.Namespace) -> None:
    """Add an A record to host. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, ip, force, macaddress)
    """
    name: str = args.name
    ip: str = args.ip
    macaddress: str | None = args.macaddress
    force: bool = args.force

    _ip_add(name, ip, macaddress, force, 4)


@command_registry.register_command(
    prog="a_change",
    description=(
        "Change an A record for the target host. If NAME is an alias the cname host is used."
    ),
    short_desc="Change A record.",
    flags=[
        Flag(
            "name",
            description="Name of the target host.",
            short_desc="Host name.",
            metavar="NAME",
        ),
        Flag(
            "-old",
            description="The existing IP that should be changed.",
            short_desc="IP to change.",
            required=True,
            metavar="IP",
        ),
        Flag(
            "-new",
            description=(
                "The new IP address. May also be a network, in which "
                "case a random IP from that network is chosen."
            ),
            short_desc="New IP.",
            required=True,
            metavar="IP/network",
        ),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def a_change(args: argparse.Namespace) -> None:
    """Change A record. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, old, new, force)
    """
    name: str = args.name
    old: str = args.old
    new: str = args.new
    force: bool = args.force

    _ip_change(name, old, new, force, 4)


@command_registry.register_command(
    prog="a_move",
    description="Move A record from a host to another host",
    short_desc="Move A record",
    flags=[
        Flag("-ip", description="IP to move", required=True, metavar="IP"),
        Flag(
            "-fromhost",
            description="Name of source host",
            required=True,
            metavar="NAME",
        ),
        Flag(
            "-tohost",
            description="Name of destination host",
            required=True,
            metavar="NAME",
        ),
    ],
)
def a_move(args: argparse.Namespace) -> None:
    """Move an IP from a host to another host. Will move also move the PTR, if any.

    :param args: argparse.Namespace (ip, fromhost, tohost)
    """
    ip: str = args.ip
    fromhost: str = args.fromhost
    tohost: str = args.tohost

    _ip_move(ip, fromhost, tohost, 4)


@command_registry.register_command(
    prog="a_remove",
    description="Remove an A record from the target host.",
    short_desc="Remove A record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("ip", description="IP to remove.", metavar="IP"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def a_remove(args: argparse.Namespace) -> None:
    """Remove A record from host.

    If <name> is a CNAME, force is required.

    :param args: argparse.Namespace (name, ip, force)
    """
    name: str = args.name
    ip: str = args.ip
    force: bool = args.force

    _ip_remove(name, ip, 4, force)


@command_registry.register_command(
    prog="a_show",
    description="Show hosts ipaddresses. If NAME is an alias the cname host is used.",
    short_desc="Show ipaddresses.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def a_show(args: argparse.Namespace) -> None:
    """Show hosts ipaddresses. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name
    client = get_client()
    host = resolve_host(client, name)
    output_host_ipaddresses(host, only=4)


@command_registry.register_command(
    prog="aaaa_add",
    description="Add an AAAA record to host. If NAME is an alias the cname host is used.",
    short_desc="Add AAAA record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag(
            "ip",
            description="The IPv6 to add to the target host.",
            metavar="IPv6",
        ),
        Flag("-macaddress", description="Mac address", metavar="MACADDRESS"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def aaaa_add(args: argparse.Namespace) -> None:
    """Add an AAAA record to host. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, ip, force, macaddress)
    """
    name: str = args.name
    ip: str = args.ip
    macaddress: str | None = args.macaddress
    force: bool = args.force

    _ip_add(name, ip, macaddress, force, 6)


@command_registry.register_command(
    prog="aaaa_change",
    description="Change AAAA record. If NAME is an alias the cname host is used.",
    short_desc="Change AAAA record.",
    flags=[
        Flag(
            "name",
            description="Name of the target host.",
            short_desc="Host name.",
            metavar="NAME",
        ),
        Flag(
            "-old",
            description="The existing IPv6 that should be changed.",
            short_desc="IPv6 to change.",
            required=True,
            metavar="IPv6",
        ),
        Flag(
            "-new",
            description="The new IPv6 address.",
            short_desc="New IPv6.",
            required=True,
            metavar="IPv6",
        ),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def aaaa_change(args: argparse.Namespace) -> None:
    """Change AAAA record. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, old, new, force)
    """
    name: str = args.name
    old: str = args.old
    new: str = args.new
    force: bool = args.force

    _ip_change(name, old, new, force, 6)


@command_registry.register_command(
    prog="aaaa_move",
    description="Move AAAA record from a host to another host",
    short_desc="Move AAAA record",
    flags=[
        Flag("-ip", description="IP to move", required=True, metavar="IP"),
        Flag(
            "-fromhost",
            description="Name of source host",
            required=True,
            metavar="NAME",
        ),
        Flag(
            "-tohost",
            description="Name of destination host",
            required=True,
            metavar="NAME",
        ),
    ],
)
def aaaa_move(args: argparse.Namespace) -> None:
    """Move an IP from a host to another host. Will move also move the PTR, if any.

    :param args: argparse.Namespace (ip, fromhost, tohost)
    """
    ip: str = args.ip
    fromhost: str = args.fromhost
    tohost: str = args.tohost

    _ip_move(ip, fromhost, tohost, 6)


@command_registry.register_command(
    prog="aaaa_remove",
    description="Remove AAAA record from host. If NAME is an alias the cname host is used.",
    short_desc="Remove AAAA record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("ip", description="IPv6 to remove.", metavar="IPv6"),
        Flag("-force", action="store_true", description="Enable force."),
    ],
)
def aaaa_remove(args: argparse.Namespace) -> None:
    """Remove AAAA record from host.

    If <name> is a CNAME, force is required.

    :param args: argparse.Namespace (name, ip, force)
    """
    name: str = args.name
    ip: str = args.ip
    force: bool = args.force

    _ip_remove(name, ip, 6, force)


@command_registry.register_command(
    prog="aaaa_show",
    description="Show hosts AAAA records. If NAME is an alias the cname host is used.",
    short_desc="Show AAAA records.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
    ],
)
def aaaa_show(args: argparse.Namespace) -> None:
    """Show hosts ipaddresses.

    If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name)
    """
    name: str = args.name

    client = get_client()
    host = resolve_host(client, name)
    output_host_ipaddresses(host, only=6)
