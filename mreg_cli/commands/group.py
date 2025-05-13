"""Hostgroups commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import Host, HostGroup
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import CreateError, DeleteError, EntityNotFound, ForceMissing
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

command_registry = CommandRegistry()


class GroupCommands(BaseCommand):
    """Group commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the group commands."""
        super().__init__(cli, command_registry, "group", "Manage hostgroups.", "Manage hostgroups")


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
    HostGroup.get_by_field_and_raise("name", args.name)
    newgroup = HostGroup.create(params={"name": args.name, "description": args.description})
    if not newgroup:
        raise CreateError("Failed to create new group '{args.name}'")

    OutputManager().add_ok(f"Created new group {newgroup.name}")


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
    for name in args.name:
        HostGroup.get_by_name_or_raise(name).output()


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
    group = HostGroup.get_by_name_or_raise(args.oldname)
    HostGroup.get_by_name_and_raise(args.newname)
    group.rename(args.newname)
    OutputManager().add_ok(f"Renamed group {args.oldname!r} to {args.newname!r}")


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
    group = HostGroup.get_by_name_or_raise(args.name)
    group.output_members(expand=args.expand)


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
    group = HostGroup.get_by_name_or_raise(args.name)
    if (group.hosts or group.groups) and not args.force:
        raise ForceMissing("Group contains hosts or groups, must force")

    if not group.delete():
        raise DeleteError(f"Failed to delete group {args.name}")

    OutputManager().add_ok(f"Deleted group {args.name!r}")


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
    sourcegroups = [HostGroup.get_by_name_or_raise(name) for name in args.srcgroup]
    destgroup = HostGroup.get_by_name_or_raise(args.dstgroup)

    for src in sourcegroups:
        destgroup.add_group(src.name)
        OutputManager().add_ok(f"Added group {src.name!r} to {destgroup.name!r}")


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
    ownergroup = HostGroup.get_by_name_or_raise(args.dstgroup)

    for name in args.srcgroup:
        if not ownergroup.has_group(name):
            raise EntityNotFound(f"Group {name!r} not a member in {ownergroup.name!r}")

    for name in args.srcgroup:
        ownergroup.remove_group(name)
        OutputManager().add_ok(f"Removed group {name!r} from {ownergroup.name!r}")


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
    hostgroup = HostGroup.get_by_name_or_raise(args.group)

    for name in args.hosts:
        host = Host.get_by_any_means_or_raise(name)
        fqname = host.name
        hostgroup.add_host(fqname)
        OutputManager().add_ok(f"Added host {fqname!r} to {args.group!r}")


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
    hostgroup = HostGroup.get_by_name_or_raise(args.group)

    to_remove: set[str] = set()
    for name in args.hosts:
        host = Host.get_by_any_means_or_raise(name)
        fqname = host.name
        if not hostgroup.has_host(fqname):
            raise EntityNotFound(f"Host {name!r} ({fqname!r}) not a member in {args.group!r}")
        to_remove.add(fqname)

    for name in to_remove:
        hostgroup.remove_host(name)
        OutputManager().add_ok(f"Removed host {name!r} from {args.group!r}")


@command_registry.register_command(
    prog="host_list",
    description="List host's group memberships",
    short_desc="List host's group memberships",
    flags=[
        Flag("host", description="hostname", metavar="HOST"),
        Flag(
            "-traverse-hostgroups",
            action="store_true",
            description="Show memberships of all parent groups as well as direct groups.",
            short_desc="Traverse hostgroups.",
        ),
    ],
)
def host_list(args: argparse.Namespace) -> None:
    """List group memberships for host.

    :param args: argparse.Namespace (host, traverse-hostgroups)
    """
    host = Host.get_by_any_means_or_raise(args.host)
    HostGroup.output_multiple(
        host.get_hostgroups(traverse=args.traverse_hostgroups), multiline=True
    )


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
    hostgroup = HostGroup.get_by_name_or_raise(args.group)

    for name in args.owners:
        hostgroup.add_owner(name)
        OutputManager().add_ok(f"Added owner {name!r} to {args.group!r}")


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
    hostgroup = HostGroup.get_by_name_or_raise(args.group)

    for name in args.owners:
        if not hostgroup.has_owner(name):
            raise EntityNotFound(f"Owner {name!r} not a member in {args.group!r}")

    for name in args.owners:
        hostgroup.remove_owner(name)
        OutputManager().add_ok(f"Removed owner {name!r} from {args.group!r}")


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
    HostGroup.get_by_name_or_raise(args.name).set_description(args.description)
    OutputManager().add_ok(f"Updated description to {args.description!r} for {args.name!r}")


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
    HostGroup.output_history(args.name)
