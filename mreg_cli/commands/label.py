"""Label-related commands for mreg_cli."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.api.models import Label
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import EntityNotFound, InputFailure
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

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
        raise InputFailure("The label name can't contain spaces.")

    # We can't do a fetch_after_create here because the API is... broken.
    # https://github.com/unioslo/mreg/blob/eed5c154bcc47b1dea474feabad46125ebde0aec/mreg/api/v1/views_labels.py#L30
    # https://github.com/unioslo/mreg/blob/eed5c154bcc47b1dea474feabad46125ebde0aec/mreg/api/v1/views.py#L187
    Label.create({"name": args.name, "description": args.description}, fetch_after_create=False)
    OutputManager().add_ok(f'Added label "{args.name}"')


@command_registry.register_command(
    prog="list", description="List labels", short_desc="List labels", flags=[]
)
def label_list(_: argparse.Namespace) -> None:
    """List labels."""
    labels = Label.get_all()
    if not labels:
        OutputManager().add_line("No labels")
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
    label = Label.get_by_name_or_raise(args.name)
    if not label:
        raise EntityNotFound(f'Label "{args.name}" does not exist.')

    label.delete()
    OutputManager().add_ok(f'Removed label "{args.name}"')


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
    Label.get_by_name_or_raise(args.name).output()


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
    ],
)
def label_rename(args: argparse.Namespace) -> None:
    """Rename a label.

    :param args: argparse.Namespace (oldname, newname)
    """
    Label.get_by_name_or_raise(args.oldname).rename(args.newname)
    OutputManager().add_ok(f'Renamed label "{args.oldname}" to "{args.newname}"')


@command_registry.register_command(
    prog="set_description",
    description="Set the description for the label",
    short_desc="Describe a label",
    flags=[
        Flag(
            "name",
            short_desc="name",
            description="The name of the label",
        ),
        Flag(
            "desc",
            short_desc="New description",
            description="The new description of the label",
        ),
    ],
)
def label_redesc(args: argparse.Namespace) -> None:
    """Change the description of a label.

    :param args: argparse.Namespace (name, desc)
    """
    Label.get_by_name_or_raise(args.name).set_description(args.desc)
    OutputManager().add_ok(f'Set description for label "{args.name}" to "{args.desc}"')
