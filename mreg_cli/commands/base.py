"""Base command class for mreg_cli.

This module provides the :py:class:`BaseCommands` class, which is used as the
base class for all CLI command classes.

Note: Logging in this file is hard as logging is not configured when this is loaded.
"""

from __future__ import annotations

from typing import Any

from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.types import CommandFunc, Flag


class BaseCommand:
    """Base class for CLI commands."""

    def __init__(
        self,
        cli: Any,
        command_registry: CommandRegistry,
        command_name: str,
        description: str,
        short_desc: str | None,
        callback: CommandFunc | None = None,
    ) -> None:
        """Initialize the command class."""
        self.base_cli = cli
        self.command_registry = command_registry
        if not command_registry.root:
            self.scope = cli.add_command(
                prog=command_name,
                description=description,
                short_desc=short_desc or description,
                callback=callback,
            )
        else:
            self.scope = cli

    def register_all_commands(self) -> None:
        """Register all commands currently in the registry."""
        for prog, description, short_desc, callback, flags in self.command_registry.get_commands():
            self.add_command(prog, description, short_desc, callback, flags)

    def add_command(
        self,
        prog: str,
        description: str,
        short_desc: str,
        callback: CommandFunc,
        flags: list[Flag] | None = None,
    ) -> None:
        """Add a command to the registry."""
        self.scope.add_command(
            prog=prog,
            description=description,
            short_desc=short_desc,
            callback=callback,
            flags=flags,
        )
