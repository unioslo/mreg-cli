"""Backnet subcommands for the host command.

Commands implemented:

    - bacnetid_add
    - bacnetid_remove
    - bacnetid_list
"""

import argparse

from mreg_cli.commands.host import registry as command_registry
from mreg_cli.log import cli_error, cli_info
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get, get_list, post
from mreg_cli.utilities.host import host_info_by_name

BACNET_MAX_ID = 4194302


@command_registry.register_command(
    prog="bacnetid_add",
    description="Assign a BACnet ID to the host.",
    short_desc="Add BACnet ID",
    flags=[
        Flag("name", description="Name of host.", metavar="NAME"),
        Flag("-id", description="ID value (0-4194302)", metavar="ID"),
    ],
)
def bacnetid_add(args: argparse.Namespace) -> None:
    """Assign a BACnet ID to the host.

    :param args: argparse.Namespace (name, id)
    """
    info = host_info_by_name(args.name)
    if "bacnetid" in info and info["bacnetid"] is not None:
        cli_error("{} already has BACnet ID {}.".format(info["name"], info["bacnetid"]["id"]))
    postdata = {"hostname": info["name"]}
    path = "/api/v1/bacnet/ids/"
    bacnetid = args.id
    if bacnetid:
        response = get(path + bacnetid, ok404=True)
        if response:
            j = response.json()
            cli_error("BACnet ID {} is already in use by {}".format(j["id"], j["hostname"]))
        postdata["id"] = bacnetid
    post(path, **postdata)
    info = host_info_by_name(args.name)
    if "bacnetid" in info and info["bacnetid"] is not None:
        b = info["bacnetid"]
        cli_info("Assigned BACnet ID {} to {}".format(b["id"], info["name"]), print_msg=True)


@command_registry.register_command(
    prog="bacnetid_remove",
    description="Unassign the BACnet ID from the host.",
    short_desc="Remove BACnet ID",
    flags=[
        Flag("name", description="Name of host.", metavar="NAME"),
    ],
)
def bacnetid_remove(args: argparse.Namespace) -> None:
    """Unassign the BACnet ID from the host.

    :param args: argparse.Namespace (name)
    """
    info = host_info_by_name(args.name)
    if "bacnetid" not in info or info["bacnetid"] is None:
        cli_error("{} does not have a BACnet ID assigned.".format(info["name"]))
    path = "/api/v1/bacnet/ids/{}".format(info["bacnetid"]["id"])
    delete(path)
    cli_info(
        "Unassigned BACnet ID {} from {}".format(info["bacnetid"]["id"], info["name"]),
        print_msg=True,
    )


@command_registry.register_command(
    prog="bacnetid_list",
    description="Find/list BACnet IDs and hostnames by ID.",
    short_desc="List used BACnet IDs",
    flags=[
        Flag(
            "-min",
            description="Minimum ID value (0-4194302)",
            flag_type=int,
            metavar="MIN",
        ),
        Flag(
            "-max",
            description="Maximum ID value (0-4194302)",
            flag_type=int,
            metavar="MAX",
        ),
    ],
)
def bacnetid_list(args: argparse.Namespace) -> None:
    """Find/list BACnet IDs and hostnames by ID.

    :param args: argparse.Namespace (min, max)
    """
    minval = 0
    if args.min is not None:
        minval = args.min
        if minval < 0:
            cli_error("The minimum ID value is 0.")
    maxval = 4194302
    if args.max is not None:
        maxval = args.max
        if maxval > BACNET_MAX_ID:
            cli_error(f"The maximum ID value is {BACNET_MAX_ID}.")
    r = get_list("/api/v1/bacnet/ids/", {"id__range": "{},{}".format(minval, maxval)})
    OutputManager().add_formatted_table(("ID", "Hostname"), ("id", "hostname"), r)
