"""Builders for error messages with underlined suggestions."""

from __future__ import annotations

import logging
import shlex
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ErrorBuilder(ABC):
    """Base class for building error messages with an underline and suggestion."""

    # Subclasses should implement this:
    SUGGESTION = ""

    # Characters used for formatting the error message
    CHAR_UNDERLINE = "^"
    CHAR_OFFSET = " "
    CHAR_SUGGESTION = "└"

    def __init__(self, command: str, exception: Exception | None = None) -> None:
        """Instantiate the builder with the command that caused the error."""
        self.command = command
        self.exception = exception

    def get_underline(self, start: int, end: int) -> str:
        """Get the underline part of the message."""
        return self.offset(self.CHAR_UNDERLINE * (end - start), start)

    def get_suggestion(self, start: int) -> str:
        """Get the suggestion part of the message."""
        msg = self.SUGGESTION
        if self.CHAR_SUGGESTION:
            msg = f"{self.CHAR_SUGGESTION} {msg}"
        return self.offset(msg, start)

    def offset(self, s: str, n: int) -> str:
        """Offset the string by n spaces."""
        return " " * n + s

    def build(self) -> str:
        """Build the error message with an underline and suggestion."""
        start, end = self.get_offset()
        lines = [
            self.command,
            self.get_underline(start, end),
            self.get_suggestion(start),
        ]
        return "\n".join(lines)

    @abstractmethod
    def get_offset(self) -> tuple[int, int]:
        """Compute the start and end index of the underlined part of the command."""
        pass


class FilterErrorBuilder(ErrorBuilder):
    """Error builder for commands with a filter."""

    SUGGESTION = "Consider enclosing this part in quotes."

    @staticmethod
    def find_word_with_char_offset(command: str, char: str) -> tuple[int, int]:
        """Find the start and end index of a word containing a specific character.

        Cannot fail; will always return a tuple of two integers.
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


def get_builder(command: str, exception: Exception | None = None) -> ErrorBuilder | None:
    """Get the appropriate error builder for the given command."""
    if "|" in command:
        return FilterErrorBuilder(command, exception)
    return None


def build_error_message(command: str, exception: Exception | None = None) -> str:
    """Build an error message with an underline and suggestion."""
    builder = get_builder(command, exception)
    if builder:
        return builder.build()
    return ""
