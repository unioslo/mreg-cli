"""Help command for the CLI."""

from __future__ import annotations

import argparse
from typing import Any

from mreg_cli.__about__ import __version__ as mreg_cli_version
from mreg_cli.api.models import ServerLibraries, ServerVersion, UserInfo
from mreg_cli.commands.base import BaseCommand
from mreg_cli.commands.registry import CommandRegistry
from mreg_cli.config import MregCliConfig
from mreg_cli.outputmanager import OutputManager

command_registry = CommandRegistry()


class HelpCommands(BaseCommand):
    """Help commands for the CLI."""

    def __init__(self, cli: Any) -> None:
        """Initialize the help commands."""
        super().__init__(
            cli,
            command_registry,
            "help",
            "Show general help for the cli. Use `help -h` to see subtopics.",
            "Help",
            callback=lambda _: cli.parser.print_help(),
        )


@command_registry.register_command("filtering", "Show help for filtering.", "Filtering Help")
def filtering_help(_: argparse.Namespace) -> None:
    """Show help for filtering."""
    print(
        """`mreg-cli` support output filtering via the operators `|` and `|!`.

The `|` operator is used to filter the output to only render the lines
matching the regular expression specified after the operator. Using `|!`
will show the lines _not_ matching.

Note that if recording to a file, filters will be applied to the output
as it would be to the terminal.

Some examples:

# No filtering
mreg> host info one.example.com
Name:         one.example.com
Contact:      me@example.com
A_Records     IP                           MAC
              192.168.1.2                  aa:bb:cc:dd:ee:ff
TTL:          (Default)
TXT:          v=spf1 -all

# Filter to only show lines containing "example"
mreg> host info one.example.com | example
Name:         one.example.com
Contact:      me@example.com

# Filter to only show lines containing "me" followed by "com"
mreg> host info one.example.com | me.*com
Contact:      me@example.com

# Filter to only show lines _not_ containing "me" followed by "com"
mreg> host info one.example.com |! me.*com
Name:         one.example.com
A_Records     IP                           MAC
              192.168.1.2                  aa:bb:cc:dd:ee:ff
TTL:          (Default)
TXT:          v=spf1 -all
"""
    )


@command_registry.register_command("configuration", "Show configuration", "Show configuration")
def configuration_help(_: argparse.Namespace) -> None:
    """Show configuration."""
    MregCliConfig().print_config_table()


@command_registry.register_command(
    "versions", "Show versions of client and server as much as possible", "Show versions"
)
def versions_help(_: argparse.Namespace) -> None:
    """Show versions of client and server as much as possible."""
    output_manager = OutputManager()
    output_manager.add_line(f"mreg-cli: {mreg_cli_version}")

    ServerVersion.fetch().output()
    ServerLibraries.fetch().output()


@command_registry.register_command(
    "whoami", "Show information about the current user", "Show user info"
)
def whoami_help(_: argparse.Namespace) -> None:
    """Show information about the current user."""
    try:
        UserInfo.fetch(ignore_errors=False).output()
    except Exception as e:
        print("Failed to fetch user info:", e)
