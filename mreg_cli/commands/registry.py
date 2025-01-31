"""Main command wrapper interface for mreg-cli.

This module provides the :py:class:`CommandWrapper` class, which is used to wrap
a command and its attributes, so it may be used as a subcommand of mreg-cli.
"""

from __future__ import annotations

from collections.abc import Callable

from mreg_cli.types import Command, CommandFunc, Flag


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
        self.root = root

    def register_command(
        self,
        prog: str,
        description: str,
        short_desc: str | None = None,
        flags: list[Flag] | None = None,
    ) -> Callable[[CommandFunc], CommandFunc]:
        """Register a command with the CLI.

        :param prog: The name of the command.
        :param description: A description of the command.
        :param short_desc: A short description of the command.
            Defaults to the full description if omitted.
        :param flags: A list of flags for the command.

        Returns a decorator that registers a command with the CLI within the
        current scope.
        """
        short_desc = short_desc or description

        def decorator(func: CommandFunc) -> CommandFunc:
            self._commands.append(Command(prog, description, short_desc, func, flags))
            return func

        return decorator

    def get_commands(self) -> list[Command]:
        """Get the list of registered commands."""
        return self._commands
