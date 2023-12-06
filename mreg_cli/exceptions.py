"""This module contains custom exceptions for the CLI."""

import sys

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML


class CliException(Exception):
    """Base exception class for the CLI."""

    def formatted_exception(self) -> str:
        """Returns a formatted string representation of the exception.

        :returns: Formatted string for the exception message.
        """
        raise NotImplementedError("This method should be implemented by subclasses")

    def print_self(self):
        """Prints the exception with appropriate formatting."""
        print_formatted_text(HTML(self.formatted_exception()), file=sys.stdout)


class CliError(CliException):
    """Exception class for CLI errors."""

    def formatted_exception(self) -> str:
        """Formatted string with ANSI red color for the error message.

        :returns: Formatted error message.
        """
        return f"<ansired>{super().__str__()}</ansired>"


class CliWarning(CliException):
    """Exception class for CLI warnings."""

    def formatted_exception(self) -> str:
        """Formatted string with HTML italic tag for the warning message.

        :returns: Formatted warning message.
        """
        return f"<i>{super().__str__()}</i>"


class HostNotFoundWarning(CliWarning):
    pass


class NetworkNotFoundWarning(CliWarning):
    pass
