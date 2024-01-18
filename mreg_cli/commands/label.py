"""Label-related commands for mreg_cli."""

import argparse
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.log import cli_info, cli_warning
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag
from mreg_cli.utilities.api import delete, get, get_list, patch, post

command_registry = CommandRegistry()


class LabelCommands(BaseCommand):
    """Label commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the label commands."""
        super().__init__(cli, command_registry, "label", "Manage host labels.", "Manage labels")


@command_registry.register_command(
    prog="add",
    description="Add a label",
    short_desc="Add a label",
    flags=[
        Flag("name", short_desc="Label name", description="The name of the new label"),
        Flag("description", description="The purpose of the label"),
    ],
)
def label_add(args: argparse.Namespace) -> None:
    """Add a label.

    :param args: argparse.Namespace (name, description)
    """
    if " " in args.name:
        OutputManager().add_line("The label name can't contain spaces.")
        return
    data = {"name": args.name, "description": args.description}
    path = "/api/v1/labels/"
    post(path, **data)
    cli_info(f'Added label "{args.name}"', True)


@command_registry.register_command(
    prog="list", description="List labels", short_desc="List labels", flags=[]
)
def label_list(_: argparse.Namespace) -> None:
    """List labels."""
    labels = get_list("/api/v1/labels/", params={"ordering": "name"})
    if not labels:
        cli_info("No labels", True)
        return
    OutputManager().add_formatted_table(("Name", "Description"), ("name", "description"), labels)


@command_registry.register_command(
    prog="remove",
    description="Remove a label",
    short_desc="Remove a label",
    flags=[
        Flag(
            "name",
            short_desc="Label name",
            description="The name of the label to remove",
        )
    ],
)
def label_delete(args: argparse.Namespace) -> None:
    """Delete a label.

    :param args: argparse.Namespace (name)
    """
    path = f"/api/v1/labels/name/{args.name}"
    delete(path)
    cli_info(f'Removed label "{args.name}"', True)


@command_registry.register_command(
    prog="info",
    description="Show details about a label",
    short_desc="Label details",
    flags=[Flag("name", short_desc="Label name", description="The name of the label")],
)
def label_info(args: argparse.Namespace) -> None:
    """Show details about a label.

    :param args: argparse.Namespace (name)
    """
    path = f"/api/v1/labels/name/{args.name}"
    label = get(path).json()
    manager = OutputManager()
    manager.add_line(f"Name:                  {label['name']}")
    manager.add_line(f"Description:           {label['description']}")

    rolelist = get_list("/api/v1/hostpolicy/roles/", params={"labels__name": args.name})
    manager.add_line("Roles with this label: ")
    if rolelist:
        for r in rolelist:
            manager.add_line("    " + r["name"])
    else:
        manager.add_line("    None")

    permlist = get_list("/api/v1/permissions/netgroupregex/", params={"labels__name": args.name})
    manager.add_line("Permissions with this label:")
    if permlist:
        OutputManager().add_formatted_table(
            ("IP range", "Group", "Reg.exp."),
            ("range", "group", "regex"),
            permlist,
            indent=4,
        )
    else:
        manager.add_line("    None")


@command_registry.register_command(
    prog="rename",
    description="Rename a label and/or change the description",
    short_desc="Rename a label",
    flags=[
        Flag(
            "oldname",
            short_desc="Old name",
            description="The old (current) name of the label",
        ),
        Flag("newname", short_desc="New name", description="The new name of the label"),
        Flag(
            "-desc",
            metavar="DESCRIPTION",
            short_desc="New description",
            description="The new description of the label",
        ),
    ],
)
def label_rename(args: argparse.Namespace) -> None:
    """Rename a label.

    :param args: argparse.Namespace (oldname, newname, desc)
    """
    path = f"/api/v1/labels/name/{args.oldname}"
    res = get(path, ok404=True)
    if not res:
        cli_warning(f'Label "{args.oldname}" does not exist.')
    data = {"name": args.newname}
    if args.desc:
        data["description"] = args.desc
    patch(path, **data)
    cli_info('Renamed label "{}" to "{}"'.format(args.oldname, args.newname), True)
