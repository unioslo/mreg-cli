"""Hostgroups commands for mreg_cli."""

import argparse
from itertools import chain
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.log import cli_error, cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get_list, patch, post
from mreg_cli.utilities.history import format_history_items, get_history_items
from mreg_cli.utilities.host import host_info_by_name

command_registry = CommandRegistry()


class GroupCommands(BaseCommand):
    """Group commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the group commands."""
        super().__init__(cli, command_registry, "group", "Manage hostgroups.", "Manage hostgroups")


def get_hostgroup(name: str) -> dict[str, Any]:
    """Get hostgroup info by name."""
    ret = get_list("/api/v1/hostgroups/", params={"name": name})
    if not ret:
        cli_warning(f'Group "{name}" does not exist')
    return ret[0]


@command_registry.register_command(
    prog="create",
    description="Create a new host group",
    short_desc="Create a new host group",
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
        Flag("description", description="Description", metavar="DESCRIPTION"),
    ],
)
def create(args: argparse.Namespace) -> None:
    """Create a new host group.

    :param args: argparse.Namespace (name, description)
    """
    ret = get_list("/api/v1/hostgroups/", params={"name": args.name})
    if ret:
        cli_error(f'Groupname "{args.name}" already in use')

    data = {"name": args.name, "description": args.description}

    path = "/api/v1/hostgroups/"
    post(path, **data)
    cli_info(f"Created new group {args.name!r}", print_msg=True)


@command_registry.register_command(
    prog="info",
    description="Shows group info with description, member count and owner(s)",
    short_desc="Group info",
    flags=[
        Flag("name", description="Group name", nargs="+", metavar="NAME"),
    ],
)
def info(args: argparse.Namespace) -> None:
    """Show host group info.

    :param args: argparse.Namespace (name)
    """
    manager = OutputManager()

    for name in args.name:
        info = get_hostgroup(name)

        manager.add_formatted_line("Name:", info["name"])
        manager.add_formatted_line("Description:", info["description"])
        members: list[str] = []
        count = len(info["hosts"])
        if count:
            members.append("{} host{}".format(count, "s" if count > 1 else ""))
        count = len(info["groups"])
        if count:
            members.append("{} group{}".format(count, "s" if count > 1 else ""))
        manager.add_formatted_line("Members:", ", ".join(members))
        if len(info["owners"]):
            owners = ", ".join([i["name"] for i in info["owners"]])
            manager.add_formatted_line("Owners:", owners)


@command_registry.register_command(
    prog="rename",
    description="Rename a group",
    short_desc="Rename a group",
    flags=[
        Flag("oldname", description="Existing name", metavar="OLDNAME"),
        Flag("newname", description="New name", metavar="NEWNAME"),
    ],
)
def rename(args: argparse.Namespace) -> None:
    """Rename group.

    :param args: argparse.Namespace (oldname, newname)
    """
    get_hostgroup(args.oldname)
    patch(f"/api/v1/hostgroups/{args.oldname}", name=args.newname)
    cli_info(f"Renamed group {args.oldname!r} to {args.newname!r}", True)


@command_registry.register_command(
    prog="list",
    description="List group members",
    short_desc="List group members",
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
        Flag("-expand", description="Expand group members", action="store_true"),
    ],
)
def group_list(args: argparse.Namespace) -> None:
    """List group members.

    :param args: argparse.Namespace (name, expand)
    """
    manager = OutputManager()

    def _format_hosts(hosts: list[dict[str, Any]], source: str = "") -> None:
        """Format hosts and add to output manager."""
        for host in hosts:
            manager.add_formatted_line_with_source("host", host["name"], source)

    def _expand_group(groupname: str) -> None:
        """Expand group and add to output manager."""
        info = get_hostgroup(groupname)
        _format_hosts(info["hosts"], source=groupname)
        for group in info["groups"]:
            _expand_group(group["name"])

    info = get_hostgroup(args.name)
    if args.expand:
        manager.add_formatted_line_with_source("Type", "Name", "Source")
        _format_hosts(info["hosts"], source=args.name)
    else:
        manager.add_formatted_line("Type", "Name")
        _format_hosts(info["hosts"])

    for group in info["groups"]:
        if args.expand:
            _expand_group(group["name"])
        else:
            manager.add_formatted_line("group", group["name"])


@command_registry.register_command(
    prog="delete",
    description="Delete host group",
    short_desc="Delete host group",
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
        Flag("-force", action="store_true", description="Enable force"),
    ],
)
def group_delete(args: argparse.Namespace) -> None:
    """Delete a host group.

    :param args: argparse.Namespace (name, force)
    """
    info = get_hostgroup(args.name)

    if (len(info["hosts"]) or len(info["groups"])) and not args.force:
        cli_error(
            "Group contains %d host(s) and %d group(s), must force"
            % (len(info["hosts"]), len(info["groups"]))
        )

    path = f"/api/v1/hostgroups/{args.name}"
    delete(path)
    cli_info(f"Deleted group {args.name!r}", print_msg=True)


@command_registry.register_command(
    prog="group_add",
    description="Add source group(s) to destination group",
    short_desc="Add group(s) to group",
    flags=[
        Flag("dstgroup", description="destination group", metavar="DSTGROUP"),
        Flag("srcgroup", description="source group", nargs="+", metavar="SRCGROUP"),
    ],
)
def group_add(args: argparse.Namespace) -> None:
    """Add group(s) to group.

    :param args: argparse.Namespace (dstgroup, srcgroup)
    """
    for name in chain([args.dstgroup], args.srcgroup):
        get_hostgroup(name)

    for src in args.srcgroup:
        data = {
            "name": src,
        }

        path = f"/api/v1/hostgroups/{args.dstgroup}/groups/"
        post(path, **data)
        cli_info(f"Added group {src!r} to {args.dstgroup!r}", print_msg=True)


@command_registry.register_command(
    prog="group_remove",
    description="Remove source group(s) from destination group",
    short_desc="Remove group(s) from group",
    flags=[
        Flag("dstgroup", description="destination group", metavar="DSTGROUP"),
        Flag("srcgroup", description="source group", nargs="+", metavar="SRCGROUP"),
    ],
)
def group_remove(args: argparse.Namespace) -> None:
    """Remove group(s) from group.

    :param args: argparse.Namespace (dstgroup, srcgroup)
    """
    info = get_hostgroup(args.dstgroup)
    group_names = {i["name"] for i in info["groups"]}
    for name in args.srcgroup:
        if name not in group_names:
            cli_warning(f"{name!r} not a group member in {args.dstgroup!r}")

    for src in args.srcgroup:
        path = f"/api/v1/hostgroups/{args.dstgroup}/groups/{src}"
        delete(path)
        cli_info(f"Removed group {src!r} from {args.dstgroup!r}", print_msg=True)


@command_registry.register_command(
    prog="host_add",
    description="Add host(s) to group",
    short_desc="Add host(s) to group",
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("hosts", description="hosts", nargs="+", metavar="HOST"),
    ],
)
def host_add(args: argparse.Namespace) -> None:
    """Add host(s) to group.

    :param args: argparse.Namespace (group, hosts)
    """
    get_hostgroup(args.group)
    info: list[dict[str, str]] = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i["name"]
        data = {
            "name": name,
        }
        path = f"/api/v1/hostgroups/{args.group}/hosts/"
        post(path, **data)
        cli_info(f"Added host {name!r} to {args.group!r}", print_msg=True)


@command_registry.register_command(
    prog="host_remove",
    description="Remove host(s) from group",
    short_desc="Remove host(s) from group",
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("hosts", description="host", nargs="+", metavar="HOST"),
    ],
)
def host_remove(args: argparse.Namespace) -> None:
    """Remove host(s) from group.

    :param args: argparse.Namespace (group, hosts)
    """
    get_hostgroup(args.group)
    info: list[dict[str, str]] = []
    for name in args.hosts:
        info.append(host_info_by_name(name, follow_cname=False))

    for i in info:
        name = i["name"]
        path = f"/api/v1/hostgroups/{args.group}/hosts/{name}"
        delete(path)
        cli_info(f"Removed host {name!r} from {args.group!r}", print_msg=True)


@command_registry.register_command(
    prog="host_list",
    description="List host's group memberships",
    short_desc="List host's group memberships",
    flags=[
        Flag("host", description="hostname", metavar="HOST"),
    ],
)
def host_list(args: argparse.Namespace) -> None:
    """List group memberships for host.

    :param args: argparse.Namespace (host)
    """
    hostname = host_info_by_name(args.host, follow_cname=False)["name"]
    group_list = get_list("/api/v1/hostgroups/", params={"hosts__name": hostname})
    if len(group_list) == 0:
        cli_info(f"Host {hostname!r} is not a member in any hostgroup", True)
        return

    manager = OutputManager()

    manager.add_line("Groups:")
    for group in group_list:
        manager.add_line(f"  {group['name']}")


@command_registry.register_command(
    prog="owner_add",
    description="Add owner(s) to group",
    short_desc="Add owner(s) to group",
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("owners", description="owners", nargs="+", metavar="OWNER"),
    ],
)
def owner_add(args: argparse.Namespace) -> None:
    """Add owner(s) to group.

    :param args: argparse.Namespace (group, owners)
    """
    get_hostgroup(args.group)

    for name in args.owners:
        data = {
            "name": name,
        }
        path = f"/api/v1/hostgroups/{args.group}/owners/"
        post(path, **data)
        cli_info(f"Added {name!r} as owner of {args.group!r}", print_msg=True)


@command_registry.register_command(
    prog="owner_remove",
    description="Remove owner(s) from group",
    short_desc="Remove owner(s) from group",
    flags=[
        Flag("group", description="group", metavar="GROUP"),
        Flag("owners", description="owner", nargs="+", metavar="OWNER"),
    ],
)
def owner_remove(args: argparse.Namespace) -> None:
    """Remove owner(s) from group.

    :param args: argparse.Namespace (group, owners)
    """
    info = get_hostgroup(args.group)
    names = {i["name"] for i in info["owners"]}
    for i in args.owners:
        if i not in names:
            cli_warning(f"{i!r} not a owner of {args.group}")

    for i in args.owners:
        path = f"/api/v1/hostgroups/{args.group}/owners/{i}"
        delete(path)
        cli_info(f"Removed {i!r} as owner of {args.group!r}", print_msg=True)


@command_registry.register_command(
    prog="set_description",
    description="Set description for group",
    short_desc="Set description for group",
    flags=[
        Flag("name", description="Group", metavar="GROUP"),
        Flag("description", description="Group description.", metavar="DESC"),
    ],
)
def set_description(args: argparse.Namespace) -> None:
    """Set description for group.

    :param args: argparse.Namespace (name, description)
    """
    get_hostgroup(args.name)
    patch(f"/api/v1/hostgroups/{args.name}", description=args.description)
    cli_info(f"updated description to {args.description!r} for {args.name!r}", True)


@command_registry.register_command(
    prog="history",
    description="Show history for group name",
    short_desc="Show history for group name",
    flags=[
        Flag("name", description="Group name", metavar="NAME"),
    ],
)
def history(args: argparse.Namespace) -> None:
    """Show host history for name.

    :param args: argparse.Namespace (name)
    """
    items = get_history_items(args.name, "group", data_relation="groups")
    format_history_items(args.name, items)
