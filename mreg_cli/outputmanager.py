"""This module contains the output management for the mreg_cli package.

This is a singleton class that manages the output for the CLI. It stores the
output lines and formats them for display. It also manages the filter for the
command.
"""

import re
from typing import Any, List, Tuple

from mreg_cli.exceptions import CliError


class OutputManager:
    """Manages and formats output for display.

    This is a singleton class to retain context between calls. It is initiated
    and cleared in the main function of the CLI, all other calls should only
    add lines to the output via add_line(), add_formatted_line(), or
    add_formatted_line_with_source(),
    """

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.clear()
        return cls._instance

    def clear(self) -> None:
        """Clears the object."""
        self._lines = []
        self._filter_re = None
        self._negate = False
        self._command = None
        self.command = None

    def has_output(self) -> bool:
        """Returns True if there is output to display."""
        return len(self._lines) > 0

    def from_command(self, command: str) -> str:
        """Adds the command that generated the output.

        :param command: The command to add.
        :raises CliError: If the command is invalid.
        :return: The cleaned command, devoid of filters and other noise.
        """
        self._command, self._filter_re, self._negate = self.get_filter(command)
        return self._command

    def add_line(self, line: str) -> None:
        """Adds a line to the output.

        :param line: The line to add.
        """
        self._lines.append(line)

    def add_formatted_line(self, key: str, value: str, padding: int = 14) -> None:
        """Formats and adds a key-value pair as a line.

        :param key: The key or label.
        :param value: The value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2}".format(padding, key, value)
        self.add_line(formatted_line)

    def add_formatted_line_with_source(
        self, key: str, value: str, source: str = "", padding: int = 14
    ) -> None:
        """Formats and adds a key-value pair as a line with a source.

        :param key: The key or label.
        :param value: The value.
        :param source: The source of the value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2:<{0}} {3}".format(padding, key, value, source)
        self.add_line(formatted_line)

    def _find_split_index(self, command: str) -> int:
        """Find the index to split the command for filtering.

        It handles both single and double quotes, ensuring that the split
        occurs outside of any quoted sections.

        :param command: The command string to be processed.
        :return: The index at which to split the command, or -1 if not found.
        """
        in_quotes = False
        current_quote = None

        for i, char in enumerate(command):
            if char in ["'", '"']:
                if in_quotes and char == current_quote:
                    in_quotes = False
                    current_quote = None
                elif not in_quotes:
                    in_quotes = True
                    current_quote = char
            elif char == "|" and not in_quotes:
                return i

        return -1

    # We want to use re.Pattern as the type here, but python 3.6 and older re-modules
    # don't have that type. So we use Any instead.
    def get_filter(self, command: str) -> Tuple[str, Any, bool]:
        """Returns the filter for the output.

        Parses the command string and extracts a filter if present, taking into
        account both single and double quoted strings to avoid incorrect
        splitting.

        :param command: The command to parse for the filter.
        :raises CliError: If the filter is invalid.
        :return: The command, the filter, and whether it is a negated filter.
        """
        negate = False
        filter_re = None

        if command:
            split_index = self._find_split_index(command)

            if split_index != -1:
                filter_str = command[split_index + 1 :].strip()
                command = command[:split_index].strip()

                if filter_str.startswith("!"):
                    negate = True
                    filter_str = filter_str[1:].strip()

                try:
                    filter_re = re.compile(filter_str)
                except re.error as exc:
                    if "|" in filter_str:
                        raise CliError(
                            "ERROR: Command parts that contain a pipe ('|') must be quoted.",
                        ) from exc
                    else:
                        raise CliError(
                            "ERROR: Unable to compile regex '{}': {}", filter_str, exc
                        ) from exc

        return (command, filter_re, negate)

    def lines(self) -> List[str]:
        """Return the lines of output.

        Note that if the command is set, and it has a filter, the lines will
        be filtered by the command's filter.
        """
        lines = self._lines
        filter_re = self._filter_re

        if filter_re is None:
            return lines

        if self._negate:
            return [line for line in lines if not filter_re.search(line)]

        return [line for line in lines if filter_re.search(line)]

    def render(self) -> None:
        """Prints the output to stdout."""
        for line in self.lines():
            print(line)

    def __str__(self) -> str:
        """Returns the formatted output as a single string."""
        return "\n".join(self._lines)
