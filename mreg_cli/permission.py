"""Permission commands for mreg_cli."""

import argparse
import ipaddress

from .cli import Flag, cli
from .history import history
from .log import cli_info, cli_warning
from .outputmanager import OutputManager
from .types import IP_network
from .util import convert_wildcard_to_regex, delete, get, get_list, is_valid_network, patch, post

###################################
#  Add the main command 'access'  #
###################################

permission = cli.add_command(
    prog="permission",
    description="Manage permissions.",
    short_desc="Manage permissions",
)


##########################################
# Implementation of sub command 'list' #
##########################################


def network_list(args: argparse.Namespace) -> None:
    """List permissions for networks.

    :param args: argparse.Namespace (group, range)
    """

    # Replace with a.supernet_of(b) when python 3.7 is required
    def _supernet_of(a: IP_network, b: IP_network) -> bool:
        """Return True if a is a supernet of b."""
        return bool(
            a.network_address <= b.network_address and a.broadcast_address >= b.broadcast_address
        )

    params = {
        "ordering": "range,group",
    }
    if args.group is not None:
        param, value = convert_wildcard_to_regex("group", args.group)
        params[param] = value
    permissions = get_list("/api/v1/permissions/netgroupregex/", params=params)

    data = []
    if args.range is not None:
        argnetwork = ipaddress.ip_network(args.range)
        for i in permissions:
            permnet = ipaddress.ip_network(i["range"])
            if argnetwork.version == permnet.version and _supernet_of(
                argnetwork, ipaddress.ip_network(i["range"])
            ):
                data.append(i)
    else:
        data = permissions

    if not data:
        cli_info("No permissions found", True)
        return

    # Add label names to the result
    labelnames = {}
    info = get_list("/api/v1/labels/")
    if info:
        for i in info:
            labelnames[i["id"]] = i["name"]
    for row in data:
        labels = []
        for j in row["labels"]:
            labels.append(labelnames[j])
        row["labels"] = ", ".join(labels)

    headers = ("Range", "Group", "Regex", "Labels")
    keys = ("range", "group", "regex", "labels")
    OutputManager().add_formatted_table(headers, keys, data)


permission.add_command(
    prog="network_list",
    description="List permissions for networks",
    short_desc="List permissions for networks",
    callback=network_list,
    flags=[
        Flag(
            "-group",
            description="Group with access (supports wildcards)",
            metavar="GROUP",
        ),
        Flag("-range", description="Network range", metavar="RANGE"),
    ],
)

##########################################
# Implementation of sub command 'add' #
##########################################


def network_add(args: argparse.Namespace) -> None:
    """Add permission for network.

    :param args: argparse.Namespace (range, group, regex)
    """
    if not is_valid_network(args.range):
        cli_warning(f"Invalid range: {args.range}")

    data = {
        "range": args.range,
        "group": args.group,
        "regex": args.regex,
    }
    path = "/api/v1/permissions/netgroupregex/"
    history.record_post(path, "", data)
    post(path, **data)
    cli_info(f"Added permission to {args.range}", True)


permission.add_command(
    prog="network_add",
    description="Add permission for network",
    short_desc="Add permission for network",
    callback=network_add,
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
    ],
)


##########################################
# Implementation of sub command 'remove' #
##########################################


def network_remove(args: argparse.Namespace) -> None:
    """Remove permission for networks.

    :param args: argparse.Namespace (range, group, regex)
    """
    params = {
        "group": args.group,
        "range": args.range,
        "regex": args.regex,
    }
    permissions = get_list("/api/v1/permissions/netgroupregex/", params=params)

    if not permissions:
        cli_warning("No matching permission found", True)
        return

    assert len(permissions) == 1, "Should only match one permission"
    identifier = permissions[0]["id"]
    path = f"/api/v1/permissions/netgroupregex/{identifier}"
    history.record_delete(path, dict(), undoable=False)
    delete(path)
    cli_info(f"Removed permission for {args.range}", True)


permission.add_command(
    prog="network_remove",
    description="Remove permission for network",
    short_desc="Remove permission for network",
    callback=network_remove,
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
    ],
)


#################################################################
# Implementation of sub commands 'label_add' and 'label_remove'
#################################################################


def add_label_to_permission(args: argparse.Namespace) -> None:
    """Add a label to a permission triplet.

    :param args: argparse.Namespace (range, group, regex, label)
    """
    # find the permission
    query = {
        "group": args.group,
        "range": args.range,
        "regex": args.regex,
    }
    permissions = get_list("/api/v1/permissions/netgroupregex/", params=query)

    if not permissions:
        cli_warning("No matching permission found", True)
        return

    assert len(permissions) == 1, "Should only match one permission"
    identifier = permissions[0]["id"]
    path = f"/api/v1/permissions/netgroupregex/{identifier}"

    # find the label
    labelpath = f"/api/v1/labels/name/{args.label}"
    res = get(labelpath, ok404=True)
    if not res:
        cli_warning(f"Could not find a label with name {args.label!r}")
    label = res.json()

    # check if the permission object already has the label
    perm = get(path).json()
    if label["id"] in perm["labels"]:
        cli_warning(f"The permission already has the label {args.label!r}")

    # patch the permission
    ar = perm["labels"]
    ar.append(label["id"])
    patch(path, labels=ar)
    cli_info(f"Added the label {args.label!r} to the permission.", print_msg=True)


permission.add_command(
    prog="label_add",
    description="Add a label to a permission",
    callback=add_label_to_permission,
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
        Flag("label", description="The label you want to add"),
    ],
)


def remove_label_from_permission(args: argparse.Namespace) -> None:
    """Remove a label from a permission.

    :param args: argparse.Namespace (range, group, regex, label)
    """
    # find the permission
    query = {
        "group": args.group,
        "range": args.range,
        "regex": args.regex,
    }
    permissions = get_list("/api/v1/permissions/netgroupregex/", params=query)

    if not permissions:
        cli_warning("No matching permission found", True)
        return

    assert len(permissions) == 1, "Should only match one permission"
    identifier = permissions[0]["id"]
    path = f"/api/v1/permissions/netgroupregex/{identifier}"

    # find the label
    labelpath = f"/api/v1/labels/name/{args.label}"
    res = get(labelpath, ok404=True)
    if not res:
        cli_warning(f"Could not find a label with name {args.label!r}")
    label = res.json()

    # check if the permission object has the label
    perm = get(path).json()
    if label["id"] not in perm["labels"]:
        cli_warning(f"The permission doesn't have the label {args.label!r}")

    # patch the permission
    ar = perm["labels"]
    ar.remove(label["id"])
    patch(path, params={"labels": ar}, use_json=True)
    cli_info(f"Removed the label {args.label!r} from the permission.", print_msg=True)


permission.add_command(
    prog="label_remove",
    description="Remove a label from a permission",
    callback=remove_label_from_permission,
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
        Flag("label", description="The label you want to remove"),
    ],
)
