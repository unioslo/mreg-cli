"""Exception handling for mreg_cli.

This module provides the ExceptionHandler class to format, log, and print
exceptions from both mreg_cli and mreg_api.
"""

from __future__ import annotations

import logging
import sys
from typing import TypeVar

import mreg_api.exceptions
from prompt_toolkit import print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.formatted_text.html import html_escape
from pydantic import ValidationError as PydanticValidationError

from mreg_cli.exceptions import CliError, CliWarning, LoginFailedError, ValidationError

logger = logging.getLogger(__name__)

T = TypeVar("T", bound=Exception)


def is_error(exc: Exception) -> bool:
    """Determine if an exception should produce an error or warning."""
    # mreg_cli errors
    if isinstance(exc, CliError):
        return True
    elif isinstance(exc, CliWarning):
        return False

    # mreg_api exceptions that should be treated as errors
    if isinstance(
        exc,
        (
            mreg_api.exceptions.DeleteError,
            mreg_api.exceptions.InternalError,
            mreg_api.exceptions.MregValidationError,
        ),
    ):
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
        exc = self.exception
        msg = html_escape(self.message)

        # Special case for LoginFailedError
        # TODO: add mapping or field in exception classes for special cases
        if isinstance(exc, (LoginFailedError, mreg_api.exceptions.LoginFailedError)):
            return f"Login failed: {msg}"

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
    ExceptionHandler(exc).handle()
