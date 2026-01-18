"""Custom exceptions for mreg_cli.

Exception handling (formatting, logging, printing) is done via standalone
functions in mreg_cli.exception_handler.
"""

from __future__ import annotations

from httpx import Response
from pydantic import ValidationError as PydanticValidationError


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
        from mreg_api.client import last_request_method, last_request_url  # noqa: PLC0415

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
    """Warning class for a network that overlaps with another network."""

    pass


class LoginFailedError(CliError):
    """Error class for login failure."""

    pass
