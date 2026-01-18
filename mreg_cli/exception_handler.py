"""Standalone exception handling functions for mreg_cli.

This module provides functions to format, log, and print exceptions from both
mreg_cli and mreg_api. It follows the pattern established in mreg_cli.output
of moving presentation logic out of classes and into standalone functions.

This allows uniform handling of exceptions regardless of which package they
originate from, since mreg_api exceptions don't have the output methods that
mreg_cli exceptions have.
"""

from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, TypeVar

import mreg_api.exceptions
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.formatted_text.html import html_escape

if TYPE_CHECKING:
    from httpx import Response
    from pydantic import ValidationError as PydanticValidationError

    from mreg_cli.exceptions import CliException, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="CliException")


def is_error(exc: Exception) -> bool:
    """Determine if an exception is an error (non-recoverable) vs a warning (recoverable).

    Errors are styled in red and indicate internal failures.
    Warnings are styled in italics and indicate user-correctable issues.

    :param exc: The exception to classify.
    :returns: True if the exception should be treated as an error.
    """
    from mreg_cli.exceptions import CliError  # noqa: PLC0415

    # mreg_cli errors
    if isinstance(exc, CliError):
        return True

    # mreg_api exceptions that should be treated as errors
    if isinstance(
        exc,
        (
            mreg_api.exceptions.InternalError,
            mreg_api.exceptions.FileError,
            mreg_api.exceptions.MregValidationError,
        ),
    ):
        return True

    return False


def format_exception(exc: Exception) -> str:
    """Format an exception for terminal display with HTML markup.

    Errors are formatted with red text, warnings with italics.

    :param exc: The exception to format.
    :returns: HTML-formatted string for display with prompt_toolkit.
    """
    from mreg_cli.exceptions import LoginFailedError  # noqa: PLC0415

    msg = html_escape(str(exc))

    # Special case for LoginFailedError
    # TODO: add mapping or field in exception classes for special cases
    if isinstance(exc, (LoginFailedError, mreg_api.exceptions.LoginFailedError)):
        return f"Login failed: {msg}"

    # Classify by severity
    if is_error(exc):
        return f"<ansired>ERROR: {msg}</ansired>"
    else:
        return f"<i>{msg}</i>"


def log_exception(exc: Exception) -> None:
    """Log an exception to logger and OutputManager.

    Errors are logged at ERROR level, warnings at WARNING level.

    :param exc: The exception to log.
    """
    from mreg_cli.exceptions import ValidationError  # noqa: PLC0415
    from mreg_cli.outputmanager import OutputManager  # noqa: PLC0415

    msg = str(exc)
    om = OutputManager()

    # ValidationError gets special logging with traceback
    if isinstance(exc, ValidationError):
        logger.exception(msg, stack_info=True, exc_info=exc)
        om.add_error(msg)
    elif is_error(exc):
        logger.error(msg)
        om.add_error(msg)
    else:
        logger.warning(msg)
        om.add_warning(msg)


def print_exception(exc: Exception) -> None:
    """Print an exception with appropriate formatting.

    :param exc: The exception to print.
    """
    print_formatted_text(HTML(format_exception(exc)), file=sys.stdout)


def handle_exception(exc: Exception) -> None:
    """Log and print an exception with appropriate formatting.

    This is the main entry point for exception handling.

    :param exc: The exception to handle.
    """
    log_exception(exc)
    print_exception(exc)


def create_exception_from_api_error(
    exc_class: type[T],
    api_error: Exception,
    message: str | None = None,
) -> T:
    """Create a CLI exception from an API error.

    Extracts the error details from the API response and creates
    a new exception with a descriptive message.

    :param exc_class: The CLI exception class to create.
    :param api_error: The original API error (mreg_cli.APIError or mreg_api.APIError).
    :param message: An optional message to prefix the error details.
    :returns: The created exception.
    """
    # Get response from either mreg_cli or mreg_api APIError
    response: Response | None = getattr(api_error, "response", None)

    if response is not None:
        parsed = mreg_api.exceptions.parse_mreg_error(response)
        if parsed and parsed.errors:
            reason = parsed.as_str()
        else:
            reason = str(api_error)
    else:
        reason = str(api_error)

    if message:
        full_message = f"{message}: {reason}"
    else:
        full_message = reason

    return exc_class(full_message)


def create_validation_error_from_pydantic(exc: PydanticValidationError) -> ValidationError:
    """Create a CLI ValidationError from a Pydantic ValidationError.

    :param exc: The Pydantic ValidationError.
    :returns: The created ValidationError.
    """
    from mreg_api.client import last_request_method, last_request_url  # noqa: PLC0415, I001

    from mreg_cli.exceptions import ValidationError  # noqa: PLC0415

    # Display a title containing the HTTP method and URL if available
    method = last_request_method.get()
    url = last_request_url.get()
    msg = f"Failed to validate {exc.title}"
    if url and method:
        msg += f" response from {method.upper()} {url}"

    exc_errors = exc.errors()

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
    return ValidationError(err_msg, exc)


def handle_pydantic_validation_error(exc: PydanticValidationError) -> None:
    """Handle a Pydantic ValidationError by converting it to a CLI ValidationError.

    :param exc: The Pydantic ValidationError to handle.
    """
    handle_exception(create_validation_error_from_pydantic(exc))
