"""Main command wrapper interface for mreg-cli.

This module provides the :py:class:`CommandWrapper` class, which is used to wrap
a command and its attributes, so it may be used as a subcommand of mreg-cli.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import NamedTuple

from mreg_cli.types import Command, CommandFunc, Flag


class Group(NamedTuple):
    """A named group of commands nested under a parent registry."""

    name: str
    description: str
    short_desc: str
    registry: CommandRegistry


class CommandRegistry:
    """A registry of commands that can be registered with the CLI.

    This class is used to register commands with the CLI. It provides a
    decorator, :py:meth:`register_command`, which can be used to register a
    command with the CLI.
    """

    def __init__(self, root: bool = False) -> None:
        """Initialize the command registry.

        :param root: Whether the command is a root command.
        """
        self._commands: list[Command] = []
        self._groups: list[Group] = []
        self.root = root

    def group(self, name: str, description: str, short_desc: str | None = None) -> CommandRegistry:
        """Create a child registry whose commands are nested under `name`.

        :param name: The name of the group (the subcommand users type).
        :param description: A description of the group.
        :param short_desc: A short description of the group.
            Defaults to the full description if omitted.
        """
        registry = CommandRegistry()
        self._groups.append(Group(name, description, short_desc or description, registry))
        return registry

    def register_command(
        self,
        prog: str,
        description: str,
        short_desc: str | None = None,
        flags: list[Flag] | None = None,
        aliases: list[str] | None = None,
    ) -> Callable[[CommandFunc], CommandFunc]:
        """Register a command with the CLI.

        :param prog: The name of the command.
        :param description: A description of the command.
        :param short_desc: A short description of the command.
            Defaults to the full description if omitted.
        :param flags: A list of flags for the command.
        :param aliases: Alternative names for the command, as space-separated
            paths relative to the root scope of the top-level registry.
            Aliases are hidden from help and completion.

        Returns a decorator that registers a command with the CLI within the
        current scope.
        """
        short_desc = short_desc or description

        def decorator(func: CommandFunc) -> CommandFunc:
            self._commands.append(Command(prog, description, short_desc, func, flags, aliases))
            return func

        return decorator

    def get_commands(self) -> list[Command]:
        """Get the list of registered commands."""
        return self._commands

    def get_groups(self) -> list[Group]:
        """Get the list of registered command groups."""
        return self._groups
