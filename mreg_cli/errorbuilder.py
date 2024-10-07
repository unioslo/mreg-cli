"""Builders for error messages with underlined suggestions."""

from __future__ import annotations

import logging
import shlex
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

ExcOrStr = Exception | str


# Re-usable function for error builders that don't need a specific implementation
def default_get_offset(self: "ErrorBuilder") -> tuple[int, int]:  # noqa: ARG001
    """Get the start and end index of the underlined part of the command."""
    return -1, -1


class ErrorBuilder(ABC):
    """Base class for building error messages with an underline and suggestion."""

    # Subclasses should implement this:
    SUGGESTION = ""

    # Characters used for formatting the error message
    CHAR_UNDERLINE = "^"
    CHAR_OFFSET = " "
    CHAR_SUGGESTION = "└"

    def __init__(self, command: str, exc_or_str: ExcOrStr) -> None:
        """Instantiate the builder with the command that caused the error."""
        self.command = command
        self.exc_or_str = exc_or_str

    def get_underline(self, start: int, end: int) -> str:
        """Get the underline part of the message.

        :param int start: The start index of the underlined part of the command.
        :param int end: The end index of the underlined part of the command.

        :returns: The underlined part of the command.
        """
        return self.offset(self.CHAR_UNDERLINE * (end - start), start)

    def get_suggestion(self, start: int) -> str:
        """Get the suggestion part of the message.

        :param int start: The start index of the underlined part of the command.
        """
        msg = self.SUGGESTION
        if self.CHAR_SUGGESTION:
            msg = f"{self.CHAR_SUGGESTION} {msg}"
        return self.offset(msg, start)

    def offset(self, s: str, n: int) -> str:
        """Offset the string by n spaces.

        :param str s: The string to offset.
        :param int n: The number of spaces to offset by.

        :returns: The offset string.
        """
        return " " * n + s

    def build(self) -> str:
        """Build the error message with an underline and suggestion.

        :returns: The error message with an underline and suggestion.
        """
        start, end = self.get_offset()
        lines = [
            self.command,
            self.get_underline(start, end),
            self.get_suggestion(start),
        ]
        # prepend the exception message if it exists
        if self.exc_or_str:
            lines.insert(0, str(self.exc_or_str))
        return "\n".join(lines)

    @abstractmethod
    def get_offset(self) -> tuple[int, int]:
        """Compute the start and end index of the underlined part of the command."""
        raise NotImplementedError

    @abstractmethod
    def can_build(self) -> bool:
        """Check if the builder can build an error message for the given command."""
        raise NotImplementedError


class FallbackErrorBuilder(ErrorBuilder):
    """Builder for errors without a specific implementation.

    Renders the error message as a single line without an underline or suggestion.
    The error message is displayed as-is.
    """

    get_offset = default_get_offset  # needed for ABC parent class

    def build(self) -> str:
        """Build the error message without an underline or suggestion."""
        return str(self.exc_or_str)

    def can_build(self) -> bool:  # noqa: D102
        return True


class FilterErrorBuilder(ErrorBuilder):
    """Error builder for commands with a filter."""

    SUGGESTION = "Consider enclosing this part in quotes."

    @staticmethod
    def find_word_with_char_offset(command: str, char: str) -> tuple[int, int]:
        """Find the start and end index of a word containing a specific character.

        Cannot fail; will always return a tuple of two integers.

        :param str command: The command to search.
        :param str char: The character to search for.

        :returns: Tuple of two integers representing the start and end index of the word.
                  Returns (-1, -1) if the character is not found.
        """
        command = command.strip()
        if not command:
            return -1, -1

        # Parse the command into parts
        cmd = shlex.split(command, posix=False)  # keep quotes and backslashes
        for part in cmd:
            # Skip parts that contain quotes
            # NOTE: This is a very naive check, and will not work for all cases
            #      (e.g. escaped quotes)
            if "'" in part or '"' in part:
                continue

            if char in part:
                try:
                    start, end = command.index(part), command.index(part) + len(part)
                    if start > end or start >= len(command) or end >= len(command):
                        raise ValueError(f"Invalid start and end values: {start}, {end}")
                except ValueError as e:
                    logger.error(
                        "Failed to get index of char '%s' in part '%s' of command %s: %s",
                        char,
                        part,
                        command,
                        e,
                    )
                else:
                    return start, end
        return -1, -1

    def get_offset(self) -> tuple[int, int]:  # noqa: D102 (missing docstring [inherit it from parent])
        return self.find_word_with_char_offset(self.command, "|")

    def can_build(self) -> bool:  # noqa: D102 (missing docstring [inherit it from parent])
        return "|" in self.command


BUILDERS: list[type[ErrorBuilder]] = [
    FilterErrorBuilder,
]


def get_builder(command: str, exc_or_str: ExcOrStr) -> ErrorBuilder:
    """Get the appropriate error builder for the given command.

    :param str command: The command that caused the error.
    :param exc_or_str: The exception or error message.

    :returns: An error builder instance.
    """
    for builder in BUILDERS:
        b = builder(command, exc_or_str)
        if b.can_build():
            return b
    return FallbackErrorBuilder(command, exc_or_str)


def build_error_message(command: str, exc_or_str: ExcOrStr) -> str:
    """Build an error message for the given command and exception.

    :param str command: The command that caused the error.
    :param exc_or_str: The exception or error message.

    :returns: Error message based on the command and exception.
    """
    builder = get_builder(command, exc_or_str)
    return builder.build()
