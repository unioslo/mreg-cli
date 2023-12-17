"""Base command class for mreg_cli.

This module provides the :py:class:`BaseCommands` class, which is used as the
base class for all CLI command classes.
"""
import argparse
from typing import Any, Callable, List, Optional

from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.types import Flag


class BaseCommand:
    """Base class for CLI commands."""

    def __init__(
        self,
        cli: Any,
        command_registry: CommandRegistry,
        command_name: str,
        description: str,
        short_desc: Optional[str],
        callback: Optional[Callable[[argparse.Namespace], None]] = None,
    ) -> None:
        """Initialize the command class."""
        self.base_cli = cli
        self.command_registry = command_registry
        self.scope = cli.add_command(
            prog=command_name,
            description=description,
            short_desc=short_desc or description,
            callback=callback,
        )

    def register_all_commands(self) -> None:
        """Register all commands currently in the registry."""
        for prog, description, short_desc, callback, flags in self.command_registry.get_commands():
            self.add_command(prog, description, short_desc, callback, flags)

    def add_command(
        self,
        prog: str,
        description: str,
        short_desc: str,
        callback: Callable[[argparse.Namespace], None],
        flags: Optional[List[Flag]] = None,
    ) -> None:
        """Add a command to the registry."""
        self.scope.add_command(
            prog=prog,
            description=description,
            short_desc=short_desc,
            callback=callback,
            flags=flags,
        )
