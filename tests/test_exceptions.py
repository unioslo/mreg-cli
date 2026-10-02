from __future__ import annotations

from typing import TypeVar

import mreg_api.exceptions
import pytest
from _pytest.mark.structures import ParameterSet
from httpx import Request, Response
from inline_snapshot import snapshot
from mreg_api.exceptions import (
    APIError,
    DeleteError,
    GetError,
    HTTPStatusError,
    InvalidAuthTokenError,
    LoginFailedError,
    PatchError,
    PostError,
    ResponseError,
    UnexpectedDataError,
    UnexpectedResponseError,
)
from mreg_api.models import Host
from pydantic import ValidationError as PydanticValidationError

from mreg_cli.exceptions import _MREG_API_ERROR_EXCEPTIONS, CliError, CliWarning, handle_exception
from tests.utils import normalize_line_endings


def _get_responseerror_warnings_params() -> list[ParameterSet]:
    """Get the list of mreg_api exception types that should be treated as warnings as pytest params"""
    params: list[ParameterSet] = []
    for obj in _get_responseerror_warnings():
        params.append(
            pytest.param(
                obj,
                id=obj.__name__,
            )
        )
    return params


def _get_responseerror_warnings() -> list[type[mreg_api.exceptions.ResponseError]]:
    """Get the list of mreg_api exception types that are warnings and carry a response."""
    exceptions: list[type[mreg_api.exceptions.ResponseError]] = []
    for obj in mreg_api.exceptions.__dict__.values():
        if (
            isinstance(obj, type)
            and issubclass(obj, mreg_api.exceptions.ResponseError)
            and obj not in _MREG_API_ERROR_EXCEPTIONS
        ):
            exceptions.append(obj)

    return exceptions


def _get_responseerror_errors_params() -> list[ParameterSet]:
    """Get the list of mreg_api exception types that should be treated as errors as pytest params."""
    params: list[ParameterSet] = []
    for obj in _get_responseerror_errors():
        params.append(
            pytest.param(
                obj,
                id=obj.__name__,
            )
        )
    return params


def _get_responseerror_errors() -> list[type[mreg_api.exceptions.ResponseError]]:
    """Get the list of mreg_api exception types that are errors and carry a response."""
    exceptions: list[type[mreg_api.exceptions.ResponseError]] = []
    for obj in mreg_api.exceptions.__dict__.values():
        if (
            isinstance(obj, type)
            and issubclass(obj, mreg_api.exceptions.ResponseError)
            and obj in _MREG_API_ERROR_EXCEPTIONS
        ):
            exceptions.append(obj)

    return exceptions


ErrorT = TypeVar("ErrorT", bound=Exception)


def _instantiate_response_error(e: type[ErrorT], message: str, method: str = "HEAD") -> ErrorT:
    if issubclass(e, mreg_api.exceptions.ResponseError):
        exc_instance = e(
            message,
            response=Response(
                status_code=400, request=Request(method=method, url="https://example.com")
            ),
        )
    else:
        exc_instance = e(message)
    return exc_instance


def test_responseerror_errors_snapshot() -> None:
    """Test snapshot of ResponseError errors."""
    exceptions = _get_responseerror_errors()
    assert exceptions == snapshot([DeleteError])


def test_responseerror_warnings_snapshot() -> None:
    """Test snapshot of ResponseError warnings."""
    exceptions = _get_responseerror_warnings()
    assert exceptions == snapshot(
        [
            ResponseError,
            APIError,
            HTTPStatusError,
            PostError,
            PatchError,
            GetError,
            UnexpectedResponseError,
            UnexpectedDataError,
            LoginFailedError,
            InvalidAuthTokenError,
        ]
    )


@pytest.mark.parametrize("exc_type", _get_responseerror_warnings_params())
def test_handle_exception_warning(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    exc_type: type[mreg_api.exceptions.ResponseError],
) -> None:
    """Test handling of ResponseError exceptions considered warnings."""
    # Use the same method for all exceptions to ensure consistent message formatting
    exc_instance = _instantiate_response_error(exc_type, "Test warning message", method="HEAD")
    handle_exception(exc_instance)

    assert caplog.record_tuples == snapshot(
        [
            (
                "mreg_cli.exceptions",
                30,
                """\
400 Bad Request: HEAD https://example.com
Test warning message\
""",
            )
        ]
    )

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot("""\
400 Bad Request: HEAD https://example.com
Test warning message
""")
    assert err == ""


@pytest.mark.parametrize("exc_type", _get_responseerror_errors_params())
def test_handle_exception_error(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    exc_type: type[mreg_api.exceptions.ResponseError],
) -> None:
    """Test handling of ResponseError exceptions considered errors."""
    exc_instance = _instantiate_response_error(exc_type, "Test error message", method="DELETE")

    # Call function and check output
    handle_exception(exc_instance)

    assert caplog.record_tuples == snapshot(
        [
            (
                "mreg_cli.exceptions",
                40,
                """\
400 Bad Request: DELETE https://example.com
Test error message\
""",
            )
        ]
    )

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot("""\
ERROR: 400 Bad Request: DELETE https://example.com
Test error message
""")
    assert err == ""


def test_handle_exception_pydantic(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test handling of Pydantic ValidationError."""
    with pytest.raises(PydanticValidationError) as exc_info:
        Host.model_validate({"name": "test"})  # Missing required fields

    # Call function and check output
    handle_exception(exc_info.value)

    assert caplog.record_tuples == snapshot(
        [
            (
                "mreg_cli.exceptions",
                40,
                """\
Failed to validate Host
  Input: {'name': 'test'}
  Errors:
    Field: created_at
    Reason: Field required

    Field: updated_at
    Reason: Field required

    Field: id
    Reason: Field required

    Field: ipaddresses
    Reason: Field required

    Field: comment
    Reason: Field required\
""",
            )
        ]
    )

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot(
        """\
ERROR: Failed to validate Host
  Input: {'name': 'test'}
  Errors:
    Field: created_at
    Reason: Field required

    Field: updated_at
    Reason: Field required

    Field: id
    Reason: Field required

    Field: ipaddresses
    Reason: Field required

    Field: comment
    Reason: Field required
"""
    )
    assert err == ""


def test_clierror_handling(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test handling of mreg_cli.exceptions.CliError."""
    exc_instance = CliError("Test CLI error message")

    # Call function and check output
    handle_exception(exc_instance)

    assert caplog.record_tuples == snapshot(
        [("mreg_cli.exceptions", 40, "Test CLI error message")]
    )

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot("ERROR: Test CLI error message\n")
    assert err == snapshot("")


def test_cliwarning_handling(
    caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    """Test handling of mreg_cli.exceptions.CliWarning."""
    exc_instance = CliWarning("Test CLI warning message")

    # Call function and check output
    handle_exception(exc_instance)

    assert caplog.record_tuples == snapshot(
        [("mreg_cli.exceptions", 30, "Test CLI warning message")]
    )

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot("Test CLI warning message\n")
    assert err == snapshot("")
