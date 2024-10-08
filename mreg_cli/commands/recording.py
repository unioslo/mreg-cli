"""Recording commands for the CLI."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import InputFailure
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag

command_registry = CommandRegistry()


class RecordingCommmands(BaseCommand):
    """Recording commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the recording commands."""
        super().__init__(
            cli,
            command_registry,
            "recording",
            "Recording commands for the CLI.",
            "Manage recording.",
        )


@command_registry.register_command(
    prog="start",
    description="Start recording commands to a file.",
    short_desc="Start recording",
    flags=[
        Flag(
            "filename",
            description="The filename to record to.",
            short_desc="Filename",
            metavar="filename",
        )
    ],
)
def start_recording(args: argparse.Namespace) -> None:
    """Start recording commands and output to the given file."""
    if not args.filename:
        raise InputFailure("No filename given.")

    OutputManager().recording_start(args.filename)


@command_registry.register_command(
    prog="stop",
    description="Stop recording commands and output to the given file.",
    short_desc="Stop recording",
)
def stop_recording(_: argparse.Namespace):
    """Stop recording commands and output to the given file."""
    OutputManager().recording_stop()
