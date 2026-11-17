"""Base command class for mreg_cli.

This module provides the :py:class:`BaseCommands` class, which is used as the
base class for all CLI command classes.

Note: Logging in this file is hard as logging is not configured when this is loaded.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import InternalError
from mreg_cli.types import Command, CommandFunc


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
        self._pending_aliases: list[tuple[str, Command]] = []
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
        """Register all commands and groups currently in the registry."""
        self._register(self.command_registry, self.scope)

    def _register(self, registry: CommandRegistry, scope: Any) -> None:
        """Recursively register a registry's commands and groups under `scope`.

        Aliases are deferred to :py:meth:`_register_aliases` so they may point
        anywhere in the command tree, regardless of registration order.
        """
        for command in registry.get_commands():
            scope.add_command(
                prog=command.prog,
                description=command.description,
                short_desc=command.short_desc,
                callback=command.callback,
                flags=command.flags,
            )
            for alias in command.aliases or []:
                self._pending_aliases.append((alias, command))
        for name, description, short_desc, sub_registry in registry.get_groups():
            group_scope = scope.add_command(
                prog=name, description=description, short_desc=short_desc
            )
            self._register(sub_registry, group_scope)

    def _register_aliases(self) -> None:
        """Register hidden aliases collected by :py:meth:`_register`.

        An alias is the full command path, e.g.
        `network policy_attribute_list`. Missing path segments, including
        top-level commands, are created ad-hoc as hidden groups. This lets
        a deprecated command category be fully removed while its aliases
        keep working.
        :raises InternalError: If an alias is empty.
        """
        for alias, command in self._pending_aliases:
            *parents, prog = alias.split() or [""]
            if not prog:
                raise InternalError(f"Empty alias for command {command.prog!r}")
            scope = self.base_cli
            for parent in parents:
                if parent not in scope.children:
                    scope.add_command(prog=parent, description="", hidden=True)
                scope = scope.children[parent]
            scope.add_command(
                prog=prog,
                description=command.description,
                short_desc=command.short_desc,
                callback=command.callback,
                flags=command.flags,
                hidden=True,
            )


def register_commands(cli: Any, command_classes: Iterable[Callable[[Any], BaseCommand]]) -> None:
    """Instantiate and register all command classes, then resolve their aliases.

    Aliases are resolved after every class has registered so they may point
    anywhere in the command tree, regardless of the order of `command_classes`.

    :param cli: The root CLI command.
    :param command_classes: Command classes taking the root CLI as their only argument.
    """
    instances = [cls(cli) for cls in command_classes]
    for instance in instances:
        instance.register_all_commands()
    for instance in instances:
        instance._register_aliases()  # noqa: SLF001 (private-member-access)
