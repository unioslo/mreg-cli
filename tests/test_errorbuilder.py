from __future__ import annotations

import pytest

from mreg_cli.errorbuilder import (
    ErrorBuilder,
    FallbackErrorBuilder,
    FilterErrorBuilder,
    build_error_message,
    get_builder,
)


@pytest.mark.parametrize(
    "command, exc_or_str, expected",
    [
        (
            r"permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\.example\.com$ oracle",
            "failed to compile regex",
            FilterErrorBuilder,
        ),
        (
            r"permission label_add other_error",
            "Other error message",
            FallbackErrorBuilder,
        ),
    ],
)
def test_get_builder(command: str, exc_or_str: str, expected: type[ErrorBuilder]) -> None:
    builder = get_builder(command, exc_or_str)
    assert builder.__class__ == expected
    assert builder.get_underline(0, 0) == ""
    assert builder.get_underline(0, 10) == "^^^^^^^^^^"
    assert builder.get_underline(5, 10) == "     ^^^^^"
    assert builder.get_suggestion(0) == ""
    assert builder.get_suggestion(5) == "  Suggestion"


@pytest.mark.parametrize(
    "command, exc_or_str, expected",
    [
        (
            r"permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\.example\.com$ oracle",
            r"Unable to compile regex 'cman)ora.*\.example\.com$ oracle'",
            r"""Unable to compile regex 'cman)ora.*\.example\.com$ oracle'
permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\.example\.com$ oracle
                                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                 └ Consider enclosing this part in quotes.""",
        ),
        (
            r"permission label_add other_error",
            "Other error message",
            "Other error message",
        ),
    ],
)
def test_build_error_message(command: str, exc_or_str: str, expected: str) -> None:
    assert build_error_message(command, exc_or_str) == expected
