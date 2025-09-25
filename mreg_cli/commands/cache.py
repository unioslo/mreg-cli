"""Cache command for the CLI."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.cache import get_cache
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.config import MregCliConfig
from mreg_cli.exceptions import CliError
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
        cache = get_cache()
        b = cache.clear()
    except Exception as e:
        OutputManager().add_error(f"Failed to clear cache: {e}")
        return
    OutputManager().add_ok(f"Cleared cache, {b} items removed")


@command_registry.register_command(
    prog="info", description="Show cache information", short_desc="Show cache info"
)
def cache_info(_: argparse.Namespace) -> None:
    """Show cache information."""
    conf = MregCliConfig()
    if not conf.cache:
        OutputManager().add_line("Cache is disabled")
        return

    cache = get_cache()
    try:
        info = cache.get_info()
        OutputManager().add_formatted_table(*info.as_table_args())
    except Exception as e:
        raise CliError(f"Failed to retrieve cache info: {e}") from e


@command_registry.register_command(
    prog="enable", description="Enable caching", short_desc="Enable caching"
)
def cache_enable(_: argparse.Namespace) -> None:
    """Enable caching."""
    conf = MregCliConfig()
    if conf.cache:
        OutputManager().add_line("Cache is already enabled")
        return

    cache = get_cache()
    cache.enable()
    conf.cache = True
    OutputManager().add_ok("Enabled cache")


@command_registry.register_command(
    prog="disable", description="Disable caching", short_desc="Disable caching"
)
def cache_disable(_: argparse.Namespace) -> None:
    """Disable caching."""
    conf = MregCliConfig()
    if not conf.cache:
        OutputManager().add_line("Cache is already disabled")
        return

    cache = get_cache()
    cache.disable()
    conf.cache = False
    OutputManager().add_ok("Cleared and disabled cache")
