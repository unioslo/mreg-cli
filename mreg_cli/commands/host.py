"""The base host command module.

There are a huge amount of commands in this module, so it is broken up into
submodules. This base module contains the registry that the submodules
add their commands to.
"""

from __future__ import annotations

import importlib
import os
import pkgutil
from typing import Any

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import InternalError

registry = CommandRegistry()


class HostCommands(BaseCommand):
    """Host command module to register all subcommands."""

    def __init__(self, cli: Any) -> None:
        """Initialize the Host commands."""
        super().__init__(cli, registry, "host", "Manage Hosts.", "Host Management")

    # This is a class method that overrides the inherited method in a rather
    # hacky way. The reason for this is that the host class is large enough
    # that it is broken up into submodules, and each submodule registers its
    # commands with the host class. This is done by importing the command
    # registry directly from the host command module.
    # The current design avoids circular imports, and removes the need to
    # explicitly import each submodule by name in this scope.
    def register_all_commands(self) -> None:
        """Register all host subcommands from different modules."""
        self._import_submodules()
        super().register_all_commands()

    def _import_submodules(self) -> None:
        """Dynamically import all submodules in the host_submodules package."""
        package_name = "mreg_cli.commands.host_submodules"
        package = importlib.import_module(package_name)

        # Get the directory path of the package
        if package.__file__ is None:
            raise InternalError(f"Unable to initalize host submodules from {package_name}")

        package_dir = os.path.dirname(package.__file__)

        # Import all submodules
        for _, module_name, _ in pkgutil.iter_modules([package_dir]):
            importlib.import_module(f"{package_name}.{module_name}")
