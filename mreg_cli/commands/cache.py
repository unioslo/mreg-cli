"""Cache command for the CLI."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.cache import cache, get_cache_info
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.outputmanager import OutputManager

command_registry = CommandRegistry()


class CacheCommands(BaseCommand):
    """Group commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the cache commands."""
        super().__init__(cli, command_registry, "cache", "Manage cache.", "Manage cache.")


@command_registry.register_command(
    prog="clear", description="Clear the cache", short_desc="Clear the cache"
)
def cache_clear(_: argparse.Namespace) -> None:
    """Clear the cache."""
    try:
        b = cache.clear()
    except Exception as e:
        OutputManager().add_error(f"Failed to clear cache: {e}")
        return
    OutputManager().add_ok(f"Cleared cache, {b} items removed.")


@command_registry.register_command(
    prog="info", description="Show cache information", short_desc="Show cache info"
)
def cache_info(_: argparse.Namespace) -> None:
    """Show cache information."""
    try:
        info = get_cache_info()
        OutputManager().add_formatted_table(*info.as_table_args())
    except Exception as e:
        OutputManager().add_error(f"Failed to retrieve cache info: {e}")
        return
