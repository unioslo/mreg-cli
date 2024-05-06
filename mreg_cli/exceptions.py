"""Custom exceptions for mreg_cli.

Note that Cli exceptions offer a print_self() method that prints the exception
with appropriate formatting. This is useful for printing exceptions in the
context of a CLI command.
"""

from __future__ import annotations

import sys

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML


class CliException(Exception):
    """Base exception class for the CLI."""

    def formatted_exception(self) -> str:
        """Return a formatted string representation of the exception.

        :returns: Formatted string for the exception message.
        """
        raise NotImplementedError("This method should be implemented by subclasses")

    def print_self(self):
        """Print the exception with appropriate formatting."""
        print_formatted_text(HTML(self.formatted_exception()), file=sys.stdout)


class CliError(CliException):
    """Exception class for CLI errors."""

    def formatted_exception(self) -> str:
        """Return a string formatted with HTML red tag for the error message.

        :returns: Formatted error message.
        """
        return f"<ansired>{super().__str__()}</ansired>"


class CliWarning(CliException):
    """Exception class for CLI warnings."""

    def formatted_exception(self) -> str:
        """Return a string formatted with HTML italic tag for the warning message.

        :returns: Formatted warning message.
        """
        return f"<i>{super().__str__()}</i>"


class CreateFailure(CliError):
    """Error class for failed creation."""

    pass


class PatchFailure(CliError):
    """Error class for failed patching."""

    pass


class DeleteFailure(CliError):
    """Error class for failed deletion."""

    pass


class EntityNotFound(CliWarning):
    """Warning class for an entity that was not found."""

    pass


class EntityAlreadyExists(CliWarning):
    """Warning class for an entity that already exists."""

    pass


class InputFailure(CliWarning):
    """Warning class for input failure."""

    pass


class ForceMissing(CliWarning):
    """Warning class for missing force flag."""

    pass


class LoginFailedError(CliException):
    """Error class for login failure."""

    def formatted_exception(self) -> str:
        """Return a string formatted with 'Login failed:' prefixing the error message.

        :returns: Formatted error message.
        """
        return f"Login failed: {super().__str__()}"

    def __str__(self) -> str:
        """Return the error message."""
        return "Login failed"

    pass
