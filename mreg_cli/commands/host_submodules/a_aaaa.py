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

import argparse

from mreg_cli.commands.host import registry as command_registry
from mreg_cli.log import cli_info, cli_warning
from mreg_cli.types import Flag, IP_Version
from mreg_cli.utilities.api import delete, patch
from mreg_cli.utilities.host import add_ip_to_host, get_requested_ip, host_info_by_name
from mreg_cli.utilities.output import output_ipaddresses
from mreg_cli.utilities.validators import is_ipversion


def _ip_change(args: argparse.Namespace, ipversion: IP_Version) -> None:
    """Change A record. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, old, new, force)
    """
    if args.old == args.new:
        cli_warning("New and old IP are equal")

    is_ipversion(args.old, ipversion)

    # Get host info or raise exception
    info = host_info_by_name(args.name)

    for i in info["ipaddresses"]:
        if i["ipaddress"] == args.old:
            ip_id = i["id"]
            break
    else:
        cli_warning('"{}" is not owned by {}'.format(args.old, info["name"]))

    new_ip = get_requested_ip(args.new, args.force, ipversion=ipversion)

    # Update A/AAAA records ip address
    path = f"/api/v1/ipaddresses/{ip_id}"
    # Cannot redo/undo since recourse name changes
    patch(path, ipaddress=new_ip)
    cli_info(
        "changed ip {} to {} for {}".format(args.old, new_ip, info["name"]),
        print_msg=True,
    )


def _ip_move(args: argparse.Namespace, ipversion: IP_Version) -> None:
    """Move an IP from a host to another host. Will move also move the PTR, if any.

    :param args: argparse.Namespace (ip, fromhost, tohost)
    :param ipversion: 4 or 6
    """
    is_ipversion(args.ip, ipversion)
    frominfo = host_info_by_name(args.fromhost)
    toinfo = host_info_by_name(args.tohost)
    ip_id = None
    for ip in frominfo["ipaddresses"]:
        if ip["ipaddress"] == args.ip:
            ip_id = ip["id"]
    ptr_id = None
    for ptr in frominfo["ptr_overrides"]:
        if ptr["ipaddress"] == args.ip:
            ptr_id = ptr["id"]
    if ip_id is None and ptr_id is None:
        cli_warning(f'Host {frominfo["name"]} have no IP or PTR with address {args.ip}')
    msg = ""
    if ip_id:
        path = f"/api/v1/ipaddresses/{ip_id}"
        patch(path, host=toinfo["id"])
        msg = f"Moved ipaddress {args.ip}"
    else:
        msg += "No ipaddresses matched. "
    if ptr_id:
        path = f"/api/v1/ptroverrides/{ptr_id}"
        patch(path, host=toinfo["id"])
        msg += "Moved PTR override."
    cli_info(msg, print_msg=True)


def _ip_remove(args: argparse.Namespace, ipversion: IP_Version) -> None:
    """Remove A record from host. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, ip)
    """
    ip_id = None

    is_ipversion(args.ip, ipversion)

    # Check that ip belongs to host
    info = host_info_by_name(args.name)
    for rec in info["ipaddresses"]:
        if rec["ipaddress"] == args.ip.lower():
            ip_id = rec["id"]
            break
    else:
        cli_warning("{} is not owned by {}".format(args.ip, info["name"]))

    # Remove ip
    path = f"/api/v1/ipaddresses/{ip_id}"
    delete(path)
    cli_info("removed ip {} from {}".format(args.ip, info["name"]), print_msg=True)


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
    add_ip_to_host(args, 4, macaddress=args.macaddress)


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
    _ip_change(args, 4)


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
    _ip_move(args, 4)


@command_registry.register_command(
    prog="a_remove",
    description="Remove an A record from the target host.",
    short_desc="Remove A record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("ip", description="IP to remove.", metavar="IP"),
    ],
)
def a_remove(args: argparse.Namespace) -> None:
    """Remove A record from host. If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, ip)
    """
    _ip_remove(args, 4)


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
    info = host_info_by_name(args.name)
    output_ipaddresses(info["ipaddresses"])
    cli_info("showed ip addresses for {}".format(info["name"]))


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
    add_ip_to_host(args, 6, macaddress=args.macaddress)


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
    _ip_change(args, 6)


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
    _ip_move(args, 6)


@command_registry.register_command(
    prog="aaaa_remove",
    description="Remove AAAA record from host. If NAME is an alias the cname host is used.",
    short_desc="Remove AAAA record.",
    flags=[
        Flag("name", description="Name of the target host.", metavar="NAME"),
        Flag("ip", description="IPv6 to remove.", metavar="IPv6"),
    ],
)
def aaaa_remove(args: argparse.Namespace) -> None:
    """Remove AAAA record from host.

    If <name> is an alias the cname host is used.

    :param args: argparse.Namespace (name, ip)
    """
    _ip_remove(args, 6)


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
    info = host_info_by_name(args.name)
    output_ipaddresses(info["ipaddresses"])
    cli_info("showed aaaa records for {}".format(info["name"]))
