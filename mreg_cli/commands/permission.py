"""Permission commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import Label, NetworkOrIP, Permission
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import DeleteError, EntityNotFound
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, QueryParams
from mreg_cli.utilities.shared import convert_wildcard_to_regex

command_registry = CommandRegistry()


class PermissionCommands(BaseCommand):
    """Permission commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the permission commands."""
        super().__init__(
            cli, command_registry, "permission", "Manage permission.", "Manage permission"
        )


@command_registry.register_command(
    prog="network_list",
    description="List permissions for networks",
    short_desc="List permissions for networks",
    flags=[
        Flag(
            "-group",
            description="Group with access (supports wildcards)",
            metavar="GROUP",
        ),
        Flag("-range", description="Network range", metavar="RANGE"),
    ],
)
def network_list(args: argparse.Namespace) -> None:
    """List permissions for networks.

    :param args: argparse.Namespace (group, range)
    """
    permission_list: list[Permission] = []

    params: QueryParams = {}
    if args.group is not None:
        param, value = convert_wildcard_to_regex("group", args.group)
        params[param] = value

    # Well, this is effin' awful. We have to fetch all permissions, but the API wants to limit
    # the number of results. We should probably fix this in the API.
    permissions = Permission.get_by_query(query=params, ordering="range,group", limit=None)

    if args.range is not None:
        argnetwork = NetworkOrIP.parse_or_raise(args.range, mode="network")

        for permission in permissions:
            permnet = permission.range
            if permnet.version != argnetwork.version:
                continue  # no warning if the networks are not comparable
            if argnetwork.supernet_of(permnet):  # type: ignore # guaranteed to be the same version
                permission_list.append(permission)
    else:
        permission_list = permissions

    if not permission_list:
        raise EntityNotFound("No permissions found")

    output: list[dict[str, str]] = []
    labelnames: dict[int, str] = {}

    for label in Label.get_all():
        labelnames[label.id] = label.name

    for permission in permission_list:
        perm_data: dict[str, str] = {}
        row_labels: list[str] = [labelnames[label] for label in permission.labels]
        perm_data["labels"] = ", ".join(row_labels)
        perm_data["range"] = str(permission.range)
        perm_data["group"] = permission.group
        perm_data["regex"] = permission.regex
        output.append(perm_data)

    OutputManager().add_formatted_table(
        ("Range", "Group", "Regex", "Labels"),
        ("range", "group", "regex", "labels"),
        output,
    )


@command_registry.register_command(
    prog="network_add",
    description="Add permission for network",
    short_desc="Add permission for network",
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
    ],
)
def network_add(args: argparse.Namespace) -> None:
    """Add permission for network.

    :param args: argparse.Namespace (range, group, regex)
    """
    NetworkOrIP.parse_or_raise(args.range, mode="network")

    query = {
        "range": args.range,
        "group": args.group,
        "regex": args.regex,
    }

    Permission.get_by_query_unique_and_raise(query)
    Permission.create(params=query)
    OutputManager().add_ok(f"Added permission to {args.range}")


@command_registry.register_command(
    prog="network_remove",
    description="Remove permission for network",
    short_desc="Remove permission for network",
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
    ],
)
def network_remove(args: argparse.Namespace) -> None:
    """Remove permission for networks.

    :param args: argparse.Namespace (range, group, regex)
    """
    query = {
        "group": args.group,
        "range": args.range,
        "regex": args.regex,
    }

    permission = Permission.get_by_query_unique_or_raise(query)
    if permission.delete():
        OutputManager().add_ok(f"Removed permission for {args.range}")
    else:
        raise DeleteError(f"Failed to remove permission for {args.range}")


@command_registry.register_command(
    prog="label_add",
    description="Add a label to a permission",
    short_desc="Add label",
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
        Flag("label", description="The label you want to add", metavar="LABEL"),
    ],
)
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
    permission = Permission.get_by_query_unique_or_raise(query)
    permission.add_label(args.label)
    OutputManager().add_ok(f"Added the label {args.label!r} to the permission.")


@command_registry.register_command(
    prog="label_remove",
    description="Remove a label from a permission",
    short_desc="Remove label",
    flags=[
        Flag("range", description="Network range", metavar="RANGE"),
        Flag("group", description="Group with access", metavar="GROUP"),
        Flag("regex", description="Regular expression", metavar="REGEX"),
        Flag("label", description="The label you want to remove", metavar="LABEL"),
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
    permission = Permission.get_by_query_unique_or_raise(query)
    permission.remove_label(args.label)
    OutputManager().add_ok(f"Removed the label {args.label!r} from the permission.")
