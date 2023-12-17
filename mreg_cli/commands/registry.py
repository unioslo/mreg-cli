"""Main command wrapper interface for mreg-cli.

This module provides the :py:class:`CommandWrapper` class, which is used to wrap
a command and its attributes, so it may be used as a subcommand of mreg-cli.
"""

import argparse
from typing import Callable, List, Optional

from mreg_cli.types import Command, Flag


class CommandRegistry:
    """A registry of commands that can be registered with the CLI.

    This class is used to register commands with the CLI. It provides a
    decorator, :py:meth:`register_command`, which can be used to register a
    command with the CLI.
    """

    def __init__(self) -> None:
        """Initialize the command registry."""
        self._commands: List[Command] = []

    def register_command(
        self,
        prog: str,
        description: str,
        short_desc: str,
        flags: Optional[List[Flag]] = None,
    ) -> Callable[[argparse.Namespace], None]:
        """Register a command with the CLI.

        :param prog: The name of the command.
        :param description: A description of the command.
        :param short_desc: A short description of the command.

        Returns a decorator that registers a command with the CLI within the
        current scope.
        """

        def decorator(
            func: Callable[[argparse.Namespace], None],
        ) -> Callable[[argparse.Namespace], None]:
            self._commands.append(Command(prog, description, short_desc, func, flags))
            return func

        return decorator

    def get_commands(self) -> List[Command]:
        """Get the list of registered commands."""
        return self._commands
