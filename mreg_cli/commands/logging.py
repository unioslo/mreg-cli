"""Logging commands for the CLI."""

from __future__ import annotations

import argparse
import os
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import InputFailure
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, LogLevel
from mreg_cli.utilities.shared import sizeof_fmt

command_registry = CommandRegistry()


class LoggingCommmands(BaseCommand):
    """Logging commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the logging commands."""
        super().__init__(
            cli,
            command_registry,
            "logging",
            "Logging commands for the CLI.",
            "Manage logging.",
        )


@command_registry.register_command(
    prog="start",
    description="Start logging commands to a given file.",
    short_desc="Start logging",
    flags=[
        Flag(
            "filename",
            description="The filename to log to.",
            short_desc="Filename",
            metavar="filename",
        ),
        Flag(
            "level",
            description="The logging level to use.",
            short_desc="Level",
            metavar="level",
            choices=LogLevel.choices(),
            default="INFO",
        ),
    ],
)
def start_logging(args: argparse.Namespace) -> None:
    """Start logging to the given file."""
    if not args.filename:
        raise InputFailure("No filename given.")

    config = MregCliConfig()
    config.stop_logging()
    config.start_logging(args.filename, args.level)


@command_registry.register_command(
    prog="stop",
    description="Stop logging.",
    short_desc="Stop logging",
)
def stop_logging(_: argparse.Namespace):
    """Stop logging."""
    MregCliConfig().stop_logging()


@command_registry.register_command(
    prog="level",
    description="Set the logging level.",
    short_desc="Set logging level",
    flags=[
        Flag(
            "level",
            description="The logging level to use.",
            short_desc="Level",
            metavar="level",
            choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        ),
    ],
)
def set_logging_level(args: argparse.Namespace) -> None:
    """Set the logging level."""
    config = MregCliConfig()
    config.stop_logging()
    config.start_logging(config.get_default_logfile(), args.level)


@command_registry.register_command(
    prog="status",
    description="Print the logging status.",
    short_desc="Logging status",
)
def logging_status(_: argparse.Namespace):
    """Print the logging status."""
    level = MregCliConfig().get_logging_level()
    file = MregCliConfig().get_default_logfile()

    lines_in_logfile = 0
    with open(file, "r") as f:
        lines_in_logfile = sum(1 for _ in f)

    filesize = sizeof_fmt(os.path.getsize(file))

    OutputManager().add_line(f"{level} > {file} ({lines_in_logfile} lines, {filesize})")
