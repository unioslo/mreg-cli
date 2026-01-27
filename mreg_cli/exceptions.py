"""Custom exceptions and exception handling for mreg_cli."""

from __future__ import annotations

import logging
import sys
from typing import TypeVar

import mreg_api.exceptions
from httpx import Response
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.formatted_text.html import html_escape
from pydantic import ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=Exception)


class CliExit(Exception):
    """Exception used to exit the CLI."""

    pass


class CliException(Exception):
    """Base exception class for the CLI."""

    pass


class CliError(CliException):
    """Exception class for CLI errors.

    Errors are not recoverable and stem from internal failures that
    the user cannot be expected to resolve.
    """

    pass


class CliWarning(CliException):
    """Exception class for CLI warnings.

    Warnings should be recoverable by changing the user input.
    """

    pass


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


class FileError(CliError):
    """Error class for file errors."""

    pass


### Begin mreg_api wrappers ###

# NOTE: These exceptions currently just wrap mreg_api exceptions,
#       since we historically used them directly in the CLI.
#       In the future, we should consider if we want to rename
#       them to avoid confusion with mreg_api exceptions.
#       Inheriting from mreg_api allows us to catch them as before.


class EntityNotFound(mreg_api.exceptions.EntityNotFound):
    """Warning class for an entity that was not found."""

    pass


class EntityAlreadyExists(mreg_api.exceptions.EntityAlreadyExists):
    """Warning class for an entity that already exists."""

    pass


class EntityOwnershipMismatch(mreg_api.exceptions.EntityOwnershipMismatch):
    """Warning class for an entity that already exists but owned by someone else."""

    pass


class InputFailure(mreg_api.exceptions.InputFailure):
    """Warning class for input failure."""

    pass


class ForceMissing(mreg_api.exceptions.ForceMissing):
    """Warning class for missing force flag."""

    pass


class IPNetworkWarning(mreg_api.exceptions.IPNetworkError):
    """Warning class for IP network/address warnings."""

    pass


class InvalidIPAddress(mreg_api.exceptions.InvalidIPAddress):
    """Warning class for an entity that is not an IP address."""

    pass


class InvalidIPv4Address(mreg_api.exceptions.InvalidIPv4Address):
    """Warning class for an entity that is not an IPv4 address."""

    pass


class InvalidIPv6Address(mreg_api.exceptions.InvalidIPv6Address):
    """Warning class for an entity that is not an IPv6 address."""

    pass


class InvalidNetwork(mreg_api.exceptions.InvalidNetwork):
    """Warning class for an entity that is not a network."""

    pass


### End mreg_api wrappers ###


class NetworkOverlap(IPNetworkWarning):
    """Warning class for a network that overlaps with another network."""

    pass


class LoginFailedError(CliError):
    """Error class for login failure."""

    pass


_MREG_API_ERROR_EXCEPTIONS = (
    mreg_api.exceptions.DeleteError,
    mreg_api.exceptions.InternalError,
    mreg_api.exceptions.MregValidationError,
)


def is_error(exc: Exception) -> bool:
    """Determine if an exception should produce an error or warning."""
    # mreg_cli errors
    if isinstance(exc, CliError):
        return True
    elif isinstance(exc, CliWarning):
        return False

    # mreg_api exceptions that should be treated as errors
    if isinstance(exc, _MREG_API_ERROR_EXCEPTIONS):
        return True

    return False


def get_exception_message(exc: Exception, *, json: bool = True) -> str:
    """Get the plain text message from an exception.

    :param exc: The exception to get the message from.
    :param json: Whether to include JSON details for mreg_api exceptions.
    :returns: The plain text message.
    """
    if isinstance(exc, mreg_api.exceptions.APIError):
        return exc.formatted_message(json=json)
    elif isinstance(exc, ValidationError):
        mreg_api.exceptions.MregValidationError.from_pydantic(exc)
    return str(exc)


class ExceptionHandler:
    """Handler for exceptions from mreg_cli and mreg_api.

    This class takes an exception, transforms it if necessary, and precomputes
    formatted messages for display. It provides methods to log and print the
    exception with appropriate styling.

    Attributes:
        exception: The (possibly transformed) exception being handled.
        original_exception: The original exception before any transformation.
        is_error: True if the exception is non-recoverable (displayed in red).
        is_validation_error: True if the exception is a ValidationError.
        message: The plain text message from the exception.
        formatted_message: HTML-formatted message for prompt_toolkit display.

    """

    def __init__(self, exc: Exception, *, json: bool = True) -> None:
        """Initialize the handler with an exception.

        :param exc: The exception to handle.
        :param json: Whether to include JSON details for mreg_api exceptions.
        """
        self.original_exception = exc
        self.exception = self._transform_exception(exc)
        self._json = json

        # Precompute flags
        self.is_error = is_error(self.exception)
        self.is_validation_error = isinstance(self.exception, ValidationError)

        # Precompute messages
        self.message = get_exception_message(self.exception, json=self._json)
        self.formatted_message = self.get_formatted_message()

    def _transform_exception(self, exc: Exception) -> Exception:
        """Transform an exception into an appropriate mreg_cli exception if needed."""
        if isinstance(exc, ValidationError):
            return mreg_api.exceptions.MregValidationError.from_pydantic(exc)
        # TODO: add more transformations as needed.
        #       Consider mapping/registry if it grows too large
        return exc

    def get_formatted_message(self) -> str:
        """Get the HTML-formatted message for prompt_toolkit display.

        Errors are formatted with red text, warnings with italics.
        """
        msg = html_escape(self.message)

        # Classify by severity
        if self.is_error:
            return f"<ansired>ERROR: {msg}</ansired>"
        else:
            return f"<i>{msg}</i>"

    def log(self) -> None:
        """Log the exception to logger and OutputManager.

        Errors are logged at ERROR level, warnings at WARNING level.
        ValidationErrors get special logging with traceback.
        """
        from mreg_cli.outputmanager import OutputManager  # noqa: PLC0415

        om = OutputManager()

        # ValidationError gets special logging with traceback
        if self.is_validation_error:
            logger.exception(self.message, stack_info=True, exc_info=self.exception)
            om.add_error(self.message)
        elif self.is_error:
            logger.error(self.message)
            om.add_error(self.message)
        else:
            logger.warning(self.message)
            om.add_warning(self.message)

    def print(self) -> None:
        """Print the exception with appropriate formatting."""
        print_formatted_text(HTML(self.formatted_message), file=sys.stdout)

    def handle(self) -> None:
        """Log and print the exception.

        This is the main entry point for complete exception handling.
        """
        self.log()
        self.print()


def handle_exception(exc: Exception) -> None:
    """Log and print an exception with appropriate formatting.

    This is the main entry point for exception handling.

    :param exc: The exception to handle.
    """
    # TODO: add JSON toggle via config here
    # possibly via verbosity level/debug flag
    ExceptionHandler(exc).handle()
