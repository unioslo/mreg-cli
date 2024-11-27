from __future__ import annotations

import pytest
from inline_snapshot import snapshot

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
            "Unable to compile regex",
            FilterErrorBuilder,
        ),
        (
            r"permission network_add 192.168.0.0/24 pg-group ^db(pg|my).*\.example\.com$",
            "Unable to compile regex",
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


def test_build_error_message_regex() -> None:
    """Test the build_error_message function with command with regex argument."""
    # Regex as part of the command
    assert build_error_message(
        r"permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\.example\.com$ oracle",
        r"Unable to compile regex 'cman)ora.*\.example\.com$ oracle'",
    ) == snapshot("""\
Unable to compile regex 'cman)ora.*\\.example\\.com$ oracle'
permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\\.example\\.com$ oracle
                                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                 └ Consider enclosing this part in quotes.\
""")


def test_build_error_message_regex_final_part() -> None:
    """Test the build_error_message function with command with regex argument as final argument."""
    # Regex as final part of the command
    assert build_error_message(
        r"permission network_add 192.168.0.0/24 pg-group ^db(pg|my).*\.example\.com$",
        r"Unable to compile regex 'db(pg|my).*\.example\.com$'",
    ) == snapshot("""\
Unable to compile regex 'db(pg|my).*\\.example\\.com$'
permission network_add 192.168.0.0/24 pg-group ^db(pg|my).*\\.example\\.com$
                                               ^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                               └ Consider enclosing this part in quotes.\
""")


def test_build_error_message_fallback_default() -> None:
    # No suggestion for this error
    assert build_error_message(
        r"permission label_add other_error", "Other error message"
    ) == snapshot("Other error message")
