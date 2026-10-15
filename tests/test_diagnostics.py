from __future__ import annotations

import doctest
import re

import pytest
from inline_snapshot import snapshot

import mreg_cli.diagnostics
from mreg_cli.diagnostics import (
    argument_split_by_separator,
    invalid_filter_regex,
    is_standalone_separator,
    tail_span,
    word_span,
)
from mreg_cli.exceptions import ArgumentSplitBySeparator, InvalidFilterRegex
from mreg_cli.outputmanager import OutputManager

COMMAND_WITH_STANDALONE_FILTER = "policy list_atoms * | *dbora*"
COMMAND_WITH_EMBEDDED_SEPARATOR = (
    r"permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\.example\.com$ oracle"
)
EMBEDDED_SEPARATOR_FILTER = r"cman)ora.*\.example\.com$ oracle"
STANDALONE_FILTER_HEADLINE = "Unable to compile regex '*dbora*': nothing to repeat at position 0"


def _compile_error(pattern: str) -> re.error:
    """Get the re.error raised when compiling an invalid pattern.

    :param pattern: The invalid regular expression.
    :return: The raised compilation error.
    """
    with pytest.raises(re.error) as exc_info:
        re.compile(pattern)
    return exc_info.value


def test_helper_doctests() -> None:
    """Run the span helpers' doctests to keep them honest."""
    results = doctest.testmod(mreg_cli.diagnostics, verbose=False)
    assert results.attempted > 0
    assert results.failed == 0


def test_invalid_filter_regex_factory() -> None:
    """Test that invalid_filter_regex builds the diagnostic from ground truth."""
    diag = invalid_filter_regex(
        COMMAND_WITH_STANDALONE_FILTER, 20, "*dbora*", _compile_error("*dbora*")
    )
    assert diag.message == STANDALONE_FILTER_HEADLINE
    assert diag.command == COMMAND_WITH_STANDALONE_FILTER
    assert diag.span == (22, 29)
    assert diag.annotation == "This part is not a valid regular expression."


def test_argument_split_by_separator_factory() -> None:
    """Test that argument_split_by_separator builds the diagnostic from ground truth."""
    diag = argument_split_by_separator(
        COMMAND_WITH_EMBEDDED_SEPARATOR, 53, EMBEDDED_SEPARATOR_FILTER
    )
    assert diag.message == rf"Unable to compile regex '{EMBEDDED_SEPARATOR_FILTER}'"
    assert diag.command == COMMAND_WITH_EMBEDDED_SEPARATOR
    assert diag.span == (49, 79)
    assert diag.annotation == "Consider enclosing this part in quotes."


def test_render_invalid_filter_regex() -> None:
    """Test underlining an invalid regex following a filter separator."""
    diag = invalid_filter_regex(
        COMMAND_WITH_STANDALONE_FILTER, 20, "*dbora*", _compile_error("*dbora*")
    )
    assert diag.render() == snapshot("""\
Unable to compile regex '*dbora*': nothing to repeat at position 0
policy list_atoms * | *dbora*
                      ^^^^^^^
                      └ This part is not a valid regular expression.\
""")


def test_render_argument_split_by_separator() -> None:
    """Test underlining an unquoted command argument unintentionally split by a filter separator `|`."""
    diag = argument_split_by_separator(
        COMMAND_WITH_EMBEDDED_SEPARATOR, 53, EMBEDDED_SEPARATOR_FILTER
    )
    assert diag.render() == snapshot("""\
Unable to compile regex 'cman)ora.*\\.example\\.com$ oracle'
permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\\.example\\.com$ oracle
                                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                 └ Consider enclosing this part in quotes.\
""")


@pytest.mark.parametrize(
    ("command", "split_index", "expected"),
    [
        pytest.param("do_thing | filter", 9, True, id="standalone"),
        pytest.param("do_thing ^(yes|no)_thing$", 14, False, id="embedded_in_regex"),
        pytest.param("do_thing |*dbora*", 9, False, id="glued_to_filter"),
        pytest.param("do_thing* |*dbora*", 10, False, id="glued_to_command"),
        pytest.param("| filter", 0, True, id="at_command_start"),
        pytest.param("do_thing |", 9, True, id="at_command_end"),
        pytest.param("do_thing | filter", 0, False, id="not_a_separator"),
        pytest.param("do_thing | filter", 99, False, id="out_of_range"),
    ],
)
def test_is_standalone_separator(command: str, split_index: int, expected: bool) -> None:
    """Test is_standalone_separator for standalone and embedded '|' separators."""
    assert is_standalone_separator(command, split_index) == expected


def test_word_span_covers_whole_word() -> None:
    """Test that word_span expands to whitespace on both sides."""
    assert word_span("do_thing ^(yes|no)_thing$", 14) == (9, 25)


def test_word_span_at_string_start() -> None:
    """Test word_span when the '|' word starts the command."""
    assert word_span("| filter", 0) == (0, 1)


@pytest.mark.parametrize("index", [-1, 25, 99])
def test_word_span_invalid_index_raises(index: int) -> None:
    """Test that word_span raises ValueError for out-of-range indices."""
    with pytest.raises(ValueError):
        word_span("do_thing ^(yes|no)_thing$", index)


def test_tail_span_covers_compiled_filter() -> None:
    """Test that tail_span covers exactly what get_filter tried to compile."""
    assert tail_span("do_thing | ^(yes|no)_thing$", 9) == (11, 27)


def test_tail_span_includes_internal_spaces() -> None:
    """Test that tail_span covers a multi-word filter, internal spaces included."""
    command = r"do_thing | cman)ora.*\.example\.com$ oracle"
    assert tail_span(command, 9) == (11, len(command))


def test_tail_span_skips_negation_marker() -> None:
    """Test that tail_span mirrors get_filter by skipping the '!' negation marker."""
    assert tail_span("do_thing | ! *dbora*", 9) == (13, 20)


@pytest.mark.parametrize(
    ("command", "split_index"),
    [
        pytest.param("do_thing |", 9, id="empty_tail"),
        pytest.param("do_thing | !", 9, id="negation_marker_only"),
        pytest.param("do_thing | filter", -1, id="negative_index"),
        pytest.param("do_thing | filter", 17, id="index_out_of_range"),
    ],
)
def test_tail_span_invalid_raises(command: str, split_index: int) -> None:
    """Test that tail_span raises ValueError on invalid index or empty tail."""
    with pytest.raises(ValueError):
        tail_span(command, split_index)


def test_get_filter_raises_invalid_filter_regex() -> None:
    """Test that get_filter raises InvalidFilterRegex for an invalid standalone filter."""
    with pytest.raises(InvalidFilterRegex) as exc_info:
        OutputManager().get_filter(COMMAND_WITH_STANDALONE_FILTER)

    exc = exc_info.value
    assert str(exc) == STANDALONE_FILTER_HEADLINE
    assert isinstance(exc.__cause__, re.error)

    diag = exc.diagnostic
    assert diag is not None
    assert diag.message == STANDALONE_FILTER_HEADLINE
    assert diag.command == COMMAND_WITH_STANDALONE_FILTER
    assert diag.span == (22, 29)
    assert diag.annotation == "This part is not a valid regular expression."


def test_get_filter_raises_argument_split_by_separator() -> None:
    """Test that get_filter raises ArgumentSplitBySeparator for an embedded '|'."""
    with pytest.raises(ArgumentSplitBySeparator) as exc_info:
        OutputManager().get_filter(COMMAND_WITH_EMBEDDED_SEPARATOR)

    exc = exc_info.value
    assert str(exc) == rf"Unable to compile regex '{EMBEDDED_SEPARATOR_FILTER}'"
    assert isinstance(exc.__cause__, re.error)

    diag = exc.diagnostic
    assert diag is not None
    assert diag.message == rf"Unable to compile regex '{EMBEDDED_SEPARATOR_FILTER}'"
    assert diag.command == COMMAND_WITH_EMBEDDED_SEPARATOR
    assert diag.span == (49, 79)
    assert diag.annotation == "Consider enclosing this part in quotes."


def test_get_filter_negated_invalid_filter_underlines_regex() -> None:
    """Test that a negated invalid filter underlines the regex, not the '!' marker."""
    with pytest.raises(InvalidFilterRegex) as exc_info:
        OutputManager().get_filter("policy list_atoms * | ! *dbora*")

    diag = exc_info.value.diagnostic
    assert diag is not None
    assert diag.message == STANDALONE_FILTER_HEADLINE
    assert diag.span == (24, 31)
