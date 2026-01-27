from __future__ import annotations

import mreg_api.exceptions
import pytest
from _pytest.mark.structures import ParameterSet
from inline_snapshot import snapshot
from mreg_api.models import Host
from pydantic import ValidationError as PydanticValidationError

from mreg_cli.exceptions import _MREG_API_ERROR_EXCEPTIONS, CliError, CliWarning, handle_exception
from tests.utils import normalize_line_endings


def _get_warning_exceptions() -> list[ParameterSet]:
    """Get the list of mreg_api exception types that should be treated as warnings."""
    params: list[ParameterSet] = []
    for obj in mreg_api.exceptions.__dict__.values():
        if (
            isinstance(obj, type)
            and issubclass(obj, mreg_api.exceptions.APIError)
            and obj not in _MREG_API_ERROR_EXCEPTIONS
        ):
            params.append(
                pytest.param(
                    obj,
                    id=obj.__name__,
                )
            )
    return params


def _get_error_exceptions() -> list[ParameterSet]:
    """Get the list of mreg_api exception types that should be treated as errors."""
    params: list[ParameterSet] = []
    for obj in _MREG_API_ERROR_EXCEPTIONS:
        params.append(
            pytest.param(
                obj,
                id=obj.__name__,
            )
        )
    return params


@pytest.mark.parametrize(
    "exc_type",
    [
        pytest.param(
            CliWarning,
            id="CliWarning",
        ),
        *_get_warning_exceptions(),
    ],
)
def test_handle_exception_warning(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    exc_type: type[Exception],
) -> None:
    """Test handling of various exceptions as warnings."""
    exc_instance = exc_type("Test warning message")

    # Call function and check output
    handle_exception(exc_instance)

    assert caplog.record_tuples == snapshot([("mreg_cli.exceptions", 30, "Test warning message")])

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot("Test warning message\n")
    assert err == ""


@pytest.mark.parametrize(
    "exc_type",
    [
        pytest.param(
            CliError,
            id="CliError",
        ),
        *_get_error_exceptions(),
    ],
)
def test_handle_exception_error(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture[str],
    exc_type: type[Exception],
) -> None:
    """Test handling of various exceptions as errors."""
    exc_instance = exc_type("Test error message")

    # Call function and check output
    handle_exception(exc_instance)

    assert caplog.record_tuples == snapshot([("mreg_cli.exceptions", 40, "Test error message")])

    out, err = capsys.readouterr()
    out = normalize_line_endings(out)
    assert out == snapshot("ERROR: Test error message\n")
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
