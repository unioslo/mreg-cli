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

from mreg_cli.api.fields import HostName, MacAddress
from mreg_cli.api.models import CNAME, Host, HostList, Network, NetworkOrIP
from mreg_cli.commands.host import registry as command_registry
from mreg_cli.exceptions import (
    DeleteError,
    EntityAlreadyExists,
    EntityNotFound,
    ForceMissing,
    InputFailure,
)
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, IP_AddressT, IP_Version


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
    hosts_using_ip = HostList.get_by_ip(ip)
    if hosts_using_ip:
        hostnames = ", ".join(hosts_using_ip.hostnames())
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

    old_ip = NetworkOrIP.parse_or_raise(old, mode="ip")

    new_ip = NetworkOrIP.validate(new)
    network = None
    if new_ip.is_network():
        network = Network.get_by_network_or_raise(str(new_ip.ip_or_network))
        new_ip = network.get_first_available_ip()
    else:
        network = Network.get_by_ip(new_ip.as_ip())
        new_ip = new_ip.as_ip()

    if old_ip.version != ipversion:
        raise InputFailure("Old IP version does not match the requested version")

    if new_ip.version != ipversion:
        raise InputFailure("New IP version does not match the requested version")

    host = Host.get_by_any_means_or_raise(name)

    host_ip = host.get_ip(old_ip)
    if not host_ip:
        raise EntityNotFound(f"Host {host} does not have IP {old_ip}")

    check_ip_constraints(new_ip, network, host, IPOperation.CHANGE, force)

    host_ip.patch(fields={"ipaddress": str(new_ip)})

    OutputManager().add_ok(f"changed ip {old} to {new_ip} for {host}")


def _ip_move(ipaddr: str, fromhost: str, tohost: str, ipversion: IP_Version) -> None:
    """Move an IP from a host to another host. Will move also move the PTR, if any.

    :param ipaddr: IP to move
    :param fromhost: Name of source host
    :param tohost: Name of destination host
    :param ipversion: 4 or 6
    """
    ip = NetworkOrIP.parse_or_raise(ipaddr, mode="ip")
    if ip.version != ipversion:
        raise InputFailure(
            f"IP version {ip.version} does not match the requested version {ipversion}"
        )

    from_host = Host.get_by_any_means_or_raise(fromhost)
    to_host = Host.get_by_any_means_or_raise(tohost)

    host_ip = from_host.get_ip(ip)

    ptr = from_host.get_ptr_override(ip)
    if not host_ip and not ptr:
        raise EntityNotFound(f"Host {from_host} has no IP or PTR with address {ip}")

    msg = ""
    if host_ip:
        host_ip.patch(fields={"host": to_host.id})
        msg = f"Moved ipaddress {ipaddr}"
    else:
        msg += "No ipaddresses matched. "

    if ptr:
        ptr.patch(fields={"host": to_host.id})
        msg += "Moved PTR override."

    OutputManager().add_line(msg)


def _ip_remove(name: str, ipaddr: str, ipversion: IP_Version, force: bool = False) -> None:
    """Remove A record from host. If <name> is an alias the cname host is used.

    :param name: Name of the target host.
    :param ipaddr: IP to remove.
    :param ipversion: 4 or 6
    """
    host = Host.get_by_any_means_or_raise(name, inform_as_cname=False, inform_as_ptr=False)
    ip = NetworkOrIP.parse_or_raise(ipaddr, mode="ip")
    if ip.version != ipversion:
        raise InputFailure(
            f"IP version {ip.version} does not match the requested version {ipversion}"
        )

    host_ip = host.get_ip(ip)
    if not host_ip:
        raise EntityNotFound(f"Host {host} does not have IP {ip}")

    # Check if we fetched the host via a CNAME.
    if not force and host.cnames:
        # Ensure arg is a valid host name with a domain
        # (e.g. "foo" -> "foo.example.com")
        name_hostname = HostName.parse_or_raise(name)
        cname = CNAME.get_by_field("name", name_hostname)
        if cname:
            raise ForceMissing(f"{cname.name} is a CNAME for {host.name}, must force.")

    if host_ip.delete():
        OutputManager().add_ok(f"Removed ipaddress {ipaddr} from {host}")
    else:
        raise DeleteError(f"Failed to remove ipaddress {ipaddr} from {host}")


def _ip_add(
    name: str,
    ipaddr: str,
    macaddress: str | None = None,
    force: bool = False,
    ipversion: IP_Version = 4,
) -> Host:
    """Add a new IP address to a host.

    :param host: Name of the host to add the IP to.
    :param ipaddr: The IP address to add.
    :param macaddress: The MAC address to add.
    :param force: Whether to force the addition.

    :return: The updated host object.
    """
    host = Host.get_by_any_means_or_raise(name)
    ip_or_net = NetworkOrIP.validate(ipaddr)

    if ipversion == 4 and (ip_or_net.is_ipv6() or ip_or_net.is_ipv6_network()):
        raise InputFailure("Use aaaa_add for IPv6 addresses")
    elif ipversion == 6 and (ip_or_net.is_ipv4() or ip_or_net.is_ipv4_network()):
        raise InputFailure("Use a_add for IPv4 addresses")

    ip = None
    network = None
    if ip_or_net.is_network():
        network = Network.get_by_network_or_raise(str(ip_or_net.ip_or_network))
        ip = network.get_first_available_ip()
    else:
        network = Network.get_by_ip(ip_or_net.as_ip())
        ip = ip_or_net.as_ip()

    check_ip_constraints(ip, network, host, IPOperation.ADD, force)

    mac = None
    if macaddress:
        mac = MacAddress.parse_or_raise(macaddress)

    host = host.add_ip(ip, mac)  # returns the refetched host
    OutputManager().add_ok(f"Added ipaddress {ip} to {host}")
    return host


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

    Host.get_by_any_means_or_raise(name).output_ipaddresses(only=4)


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

    Host.get_by_any_means_or_raise(name).output_ipaddresses(only=6)
