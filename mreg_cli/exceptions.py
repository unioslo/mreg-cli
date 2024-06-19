"""Custom exceptions for mreg_cli.

Note that Cli exceptions offer a print_self() method that prints the exception
with appropriate formatting. This is useful for printing exceptions in the
context of a CLI command.
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML


class CliExit(Exception):
    """Exception used to exit the CLI."""

    pass


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
    """Exception class for CLI errors.

    Errors are not recoverable and stem from internal failures that
    the user cannot be expected to resolve.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize the error."""
        super().__init__(*args, **kwargs)
        logging.getLogger(__name__).error(super().__str__())
        from mreg_cli.outputmanager import OutputManager

        OutputManager().add_error(super().__str__())

    def formatted_exception(self) -> str:
        """Return a string formatted with HTML red tag for the error message.

        :returns: Formatted error message.
        """
        return f"<ansired>ERROR: {super().__str__()}</ansired>"


class CliWarning(CliException):
    """Exception class for CLI warnings.

    Warnings should be recoverable by changing the user input.
    """

    def __init__(self, *args: Any, **kwargs: Any):
        """Initialize the warning."""
        super().__init__(*args, **kwargs)
        logging.getLogger(__name__).warning(super().__str__())
        from mreg_cli.outputmanager import OutputManager

        OutputManager().add_warning(super().__str__())

    def formatted_exception(self) -> str:
        """Return a string formatted with HTML italic tag for the warning message.

        :returns: Formatted warning message.
        """
        return f"<i>{super().__str__()}</i>"


class CreateError(CliError):
    """Error class for failed creation."""

    pass


class PatchError(CliError):
    """Error class for failed patching."""

    pass


class DeleteError(CliError):
    """Error class for failed deletion."""

    pass


class GetError(CliError):
    """Error class for failed retrieval."""

    pass


class InternalError(CliError):
    """Error class for internal errors."""

    pass


class APIError(CliError):
    """Error class for API errors."""

    pass


class UnexpectedDataError(APIError):
    """Error class for unexpected API data."""

    pass


class ValidationError(CliError):
    """Error class for validation failures."""

    pass


class FileError(CliError):
    """Error class for file errors."""

    pass


class APINotOk(CliWarning):
    """Warning class for API not returning OK."""

    pass


class TooManyResults(CliWarning):
    """Warning class for too many results."""

    pass


class NoHistoryFound(CliWarning):
    """Warning class for no history found."""

    pass


class EntityNotFound(CliWarning):
    """Warning class for an entity that was not found."""

    pass


class EntityAlreadyExists(CliWarning):
    """Warning class for an entity that already exists."""

    pass


class MultipleEntititesFound(CliWarning):
    """Warning class for multiple entities found."""

    pass


class EntityOwnershipMismatch(CliWarning):
    """Warning class for an entity that already exists but owned by someone else."""

    pass


class InputFailure(CliWarning):
    """Warning class for input failure."""

    pass


class ForceMissing(CliWarning):
    """Warning class for missing force flag."""

    pass


class InvalidIPAddress(CliWarning):
    """Warning class for an entity that is not an IP address."""

    pass


class InvalidIPv4Address(CliWarning):
    """Warning class for an entity that is not an IPv4 address."""

    pass


class InvalidIPv6Address(CliWarning):
    """Warning class for an entity that is not an IPv6 address."""

    pass


class InvalidNetwork(CliWarning):
    """Warning class for an entity that is not a network."""

    pass


class NetworkOverlap(CliWarning):
    """Warning class for a networkthat overlaps with another network."""

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
