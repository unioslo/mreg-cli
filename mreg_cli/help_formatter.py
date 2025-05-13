"""A formatter for the CLI that adds extra information and improves command formatting."""

from __future__ import annotations

import argparse
from typing import Any


class CustomHelpFormatter(argparse.HelpFormatter):
    """Custom help formatter to add extra information and improve command formatting."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize the formatter."""
        super().__init__(*args, **kwargs)
        self._max_help_position = 35  # Adjust this to control the indentation of help text

    def _format_action(self, action: argparse.Action) -> str:
        """Format the action with custom width.

        :param action: The argparse Action being formatted.

        :returns: Formatted action string.
        """
        # Check if this is a _SubParsersAction (used for subcommands)
        if isinstance(action, argparse._SubParsersAction):
            # Use a custom heading for subcommands
            formatted_action = "commands:\n"

            # Format each subcommand
            longest_subcommand = len(max(action.choices.keys(), key=len))
            padding = max(longest_subcommand, 20)
            for subcommand, parser in action.choices.items():
                subcommand_help = parser.description if parser.description else ""
                formatted_subcommand = f"  {subcommand:<{padding}} {subcommand_help}"
                formatted_action += formatted_subcommand + "\n"

            return formatted_action

        # Handle non-_SubParsersAction actions with default formatting
        return super()._format_action(action)
