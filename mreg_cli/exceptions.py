"""Custom exceptions and exception handling for mreg_cli."""

from __future__ import annotations

import logging
import sys
from typing import TypeVar

import mreg_api.exceptions
from httpx import Response
from mreg_api.client import last_request_method, last_request_url
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.formatted_text.html import html_escape
from pydantic import ValidationError as PydanticValidationError

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


class UnexpectedDataError(APIError):
    """Error class for unexpected API data."""

    pass


class ValidationError(CliError):
    """Error class for validation failures."""

    def __init__(self, message: str, pydantic_error: PydanticValidationError | None = None):
        """Initialize a ValidationError.

        :param message: The error message.
        :param pydantic_error: The original Pydantic ValidationError, if any.
        """
        super().__init__(message)
        self.pydantic_error = pydantic_error

    @classmethod
    def from_pydantic(cls, e: PydanticValidationError) -> ValidationError:
        """Create a ValidationError from a Pydantic ValidationError.

        :param e: The Pydantic ValidationError.
        :returns: The created ValidationError.
        """
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
                f"Field: {', '.join(str(loc) for loc in err['loc'])}",
                f"Reason: {err['msg']}",
            ]
            errors.append("\n".join(f"    {line}" for line in errlines))

        err_msg = f"{msg}\n  Input: {inp}\n  Errors:\n" + "\n\n".join(errors)
        return cls(err_msg, e)


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
        if isinstance(exc, PydanticValidationError):
            return ValidationError.from_pydantic(exc)
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
