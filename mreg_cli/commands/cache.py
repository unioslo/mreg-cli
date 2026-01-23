"""Cache command for the CLI."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_api import MregClient
from mreg_api.exceptions import CacheError

from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.exceptions import CliError
from mreg_cli.output.cache import output_cache_info
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
        client = MregClient()
        items_removed = client.clear_cache()
        OutputManager().add_ok(f"Cleared cache, {items_removed} items removed")
    except CacheError as e:
        OutputManager().add_error(f"Failed to clear cache: {e}")
        return


@command_registry.register_command(
    prog="info", description="Show cache information", short_desc="Show cache info"
)
def cache_info(_: argparse.Namespace) -> None:
    """Show cache information."""
    client = MregClient()
    if not client.cache.is_enabled:
        OutputManager().add_line("Cache is disabled.")
        return

    try:
        info = client.get_cache_info()
        if not info:
            raise Exception("No cache data available")
        output_cache_info(info)
    except Exception as e:
        raise CliError(f"Failed to retrieve cache info: {e}") from e


@command_registry.register_command(
    prog="enable", description="Enable caching", short_desc="Enable caching"
)
def cache_enable(_: argparse.Namespace) -> None:
    """Enable caching."""
    client = MregClient()
    if client.cache.is_enabled:
        OutputManager().add_line("Cache is already enabled")
        return
    client.enable_cache()
    OutputManager().add_ok("Enabled cache")


@command_registry.register_command(
    prog="disable", description="Disable caching", short_desc="Disable caching"
)
def cache_disable(_: argparse.Namespace) -> None:
    """Disable caching."""
    client = MregClient()
    if not client.cache.is_enabled:
        OutputManager().add_line("Cache is already disabled")
        return
    client.disable_cache(clear=True)
    OutputManager().add_ok("Cleared and disabled cache")
