"""Root / base commands for the CLI."""

from __future__ import annotations

import argparse
from typing import Any, NoReturn

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import CliExit
from mreg_cli.utilities.api import logout as _force_logout

command_registry = CommandRegistry(root=True)


class RootCommmands(BaseCommand):
    """Root commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the root commands."""
        super().__init__(
            cli,
            command_registry,
            "root",
            "Root commands for the CLI.",
            "Root commands.",
        )


@command_registry.register_command(
    prog="quit",
    description="Exit application.",
    short_desc="Quit",
)
def quit_mreg_cli(_: argparse.Namespace) -> NoReturn:
    """Exit application."""
    raise CliExit


@command_registry.register_command(
    prog="exit",
    description="Exit application.",
    short_desc="Quit",
)
def exit_mreg_cli(_: argparse.Namespace) -> NoReturn:
    """Exit application."""
    raise CliExit


@command_registry.register_command(
    prog="logout",
    description="Log out from mreg and exit. Will delete the token.",
    short_desc="Log out from mreg",
)
def logout(_: argparse.Namespace):
    """Log out from mreg and exit. Will delete token."""
    _force_logout()
    raise CliExit
