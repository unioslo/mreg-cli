"""Custom exceptions for mreg_cli.

Note that Cli exceptions offer a print_self() method that prints the exception
with appropriate formatting. This is useful for printing exceptions in the
context of a CLI command.
"""

from __future__ import annotations

import logging
import sys
from typing import Self

from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.formatted_text.html import html_escape
from pydantic import ValidationError as PydanticValidationError
from requests import Response

logger = logging.getLogger(__name__)


class CliExit(Exception):
    """Exception used to exit the CLI."""

    pass


class CliException(Exception):
    """Base exception class for the CLI."""

    def escape(self) -> str:
        """Get an HTML-escaped string representation of the exception."""
        return html_escape(str(self))

    def formatted_exception(self) -> str:
        """Return a formatted string representation of the exception.

        :returns: Formatted string for the exception message.
        """
        # NOTE: override this in subclasses to provide custom formatting.
        return self.escape()

    def log(self):
        """Log the exception."""
        from mreg_cli.outputmanager import OutputManager

        logger.error(str(self))
        OutputManager().add_error(str(self))

    def print_self(self):
        """Print the exception with appropriate formatting."""
        print_formatted_text(HTML(self.formatted_exception()), file=sys.stdout)

    def print_and_log(self):
        """Print the exception and log it."""
        self.log()
        self.print_self()

    @classmethod
    def from_api_error(cls, e: APIError, message: str | None = None) -> Self:
        """Create a CliError from an API error.

        :param e: The original API error.
        :param message: An optional message to prefix the original exception message.
        :returns: The created CliError.
        """
        from mreg_cli.api.errors import parse_mreg_error

        if (api_err := parse_mreg_error(e.response)) and api_err.errors:
            reason = api_err.as_str()
        else:
            reason = str(e)
        if message:
            message += f": {reason}"
        else:
            message = reason
        return cls(message)


class CliError(CliException):
    """Exception class for CLI errors.

    Errors are not recoverable and stem from internal failures that
    the user cannot be expected to resolve.
    """

    def formatted_exception(self) -> str:
        """Return a string formatted with HTML red tag for the error message.

        :returns: Formatted error message.
        """
        return f"<ansired>ERROR: {self.escape()}</ansired>"


class CliWarning(CliException):
    """Exception class for CLI warnings.

    Warnings should be recoverable by changing the user input.
    """

    def log(self):
        """Log the exception."""
        from mreg_cli.outputmanager import OutputManager

        logger.warning(str(self))
        OutputManager().add_warning(str(self))

    def formatted_exception(self) -> str:
        """Return a string formatted with HTML italic tag for the warning message.

        :returns: Formatted warning message.
        """
        return f"<i>{self.escape()}</i>"


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


class APIError(CliWarning):
    """Warning class for API errors."""

    response: Response

    def __init__(self, message: str, response: Response):
        """Initialize an APIError warning.

        :param message: The warning message.
        :param response: The response object that triggered the exception.
        """
        super().__init__(message)
        self.response = response


class UnexpectedDataError(APIError):
    """Error class for unexpected API data."""

    pass


class ValidationError(CliError):
    """Error class for validation failures."""

    def __init__(self, message: str, pydantic_error: PydanticValidationError | None = None):
        """Initialize a ValidationError.

        :param message: The error message.
        """
        super().__init__(message)
        self.pydantic_error = pydantic_error

    @classmethod
    def from_pydantic(cls, e: PydanticValidationError) -> ValidationError:
        """Create a ValidationError from a Pydantic ValidationError.

        :param e: The Pydantic ValidationError.
        :returns: The created ValidationError.
        """
        from mreg_cli.utilities.api import last_request_method, last_request_url

        # Display a title containing the HTTP method and URL if available
        method = last_request_method.get()
        url = last_request_url.get()
        msg = f"Failed to validate {e.title}"
        if url and method:
            msg += f" response from {method.upper()} {url}"

        exc_errors = e.errors()

        # Show the input used to instantiate the model if available
        inp = exc_errors[0]["input"] if exc_errors else ""

        # Show field and reason for each error
        errors: list[str] = []
        for err in exc_errors:
            errlines: list[str] = [
                f"Field: {', '.join(str(l) for l in err['loc'])}",  # noqa: E741
                f"Reason: {err['msg']}",
            ]
            errors.append("\n".join(f"    {line}" for line in errlines))

        err_msg = f"{msg}\n  Input: {inp}\n  Errors:\n" + "\n\n".join(errors)
        return cls(err_msg, e)

    def log(self):
        """Log the exception with traceback."""
        from mreg_cli.outputmanager import OutputManager

        logger.exception(str(self), stack_info=True, exc_info=self)
        OutputManager().add_error(str(self))


class FileError(CliError):
    """Error class for file errors."""

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


class MultipleEntitiesFound(CliWarning):
    """Warning class for multiple entities found."""

    pass


class EntityOwnershipMismatch(CliWarning):
    """Warning class for an entity that already exists but owned by someone else."""

    pass


class InputFailure(CliWarning, ValueError):
    """Warning class for input failure."""

    pass


class ForceMissing(CliWarning):
    """Warning class for missing force flag."""

    pass


class IPNetworkWarning(ValueError, CliWarning):
    """Warning class for IP network/address warnings."""

    pass


class InvalidIPAddress(IPNetworkWarning):
    """Warning class for an entity that is not an IP address."""

    pass


class InvalidIPv4Address(IPNetworkWarning):
    """Warning class for an entity that is not an IPv4 address."""

    pass


class InvalidIPv6Address(IPNetworkWarning):
    """Warning class for an entity that is not an IPv6 address."""

    pass


class InvalidNetwork(IPNetworkWarning):
    """Warning class for an entity that is not a network."""

    pass


class NetworkOverlap(IPNetworkWarning):
    """Warning class for a networkthat overlaps with another network."""

    pass


class LoginFailedError(CliError):
    """Error class for login failure."""

    def formatted_exception(self) -> str:
        """Return a string formatted with 'Login failed:' prefixing the error message.

        :returns: Formatted error message.
        """
        return f"Login failed: {self.escape()}"
