"""Logging commands for the CLI."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import FileError, InputFailure
from mreg_cli.log import MregCliLogger
from mreg_cli.outputmanager import OutputManager
from mreg_cli.types import Flag, LogLevel
from mreg_cli.utilities.fs import to_path
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
            "-filename",
            description="The filename to log to. Uses default log file if not given.",
            short_desc="Filename",
            metavar="filename",
            default=None,
        ),
        Flag(
            "-level",
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
    if args.filename is not None:
        log_file = to_path(args.filename)
    else:
        log_file = MregCliConfig().log_file
    level = LogLevel(args.level)

    log = MregCliLogger()
    status = log.status
    # Abort if already logging with same params
    if status.enabled and status.file == log_file and status.level == level:
        raise InputFailure(f"Logging already enabled: {status.as_str()}")
    log.start_logging(log_file, level)
    OutputManager().add_line(f"Logging started: {status.as_str()}")


@command_registry.register_command(
    prog="stop",
    description="Stop logging.",
    short_desc="Stop logging",
)
def stop_logging(_: argparse.Namespace):
    """Stop logging."""
    log = MregCliLogger()
    if not log.status.enabled:
        raise InputFailure("Logging is already disabled.")

    log.stop_logging()
    OutputManager().add_line("Logging stopped.")


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
    log = MregCliLogger()

    if not log.status.enabled:
        raise InputFailure("Logging is not enabled, cannot set level.")

    # Determine logging params
    log_file = log.status.file or config.log_file
    level = LogLevel(args.level)
    log.start_logging(log_file, level)


@command_registry.register_command(
    prog="status",
    description="Print the logging status.",
    short_desc="Logging status",
)
def logging_status(_: argparse.Namespace):
    """Print the logging status."""
    conf = MregCliConfig()

    status = MregCliLogger().status
    log_file = status.file or conf.log_file  # fallback should never be reachable...

    if not status.enabled:
        raise InputFailure("Logging is disabled.")
    elif not log_file:
        OutputManager().add_line(status.as_str())
        return

    lines_in_logfile = 0
    try:
        with open(log_file) as f:
            lines_in_logfile = sum(1 for _ in f)
    except OSError as e:
        raise FileError(f"Unable to read log file {log_file}: {e}") from e

    filesize = sizeof_fmt(log_file.stat().st_size)

    OutputManager().add_line(f"{status.as_str()} ({lines_in_logfile} lines, {filesize})")
