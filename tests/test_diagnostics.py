from __future__ import annotations

import doctest
import re

import pytest
from inline_snapshot import snapshot

import mreg_cli.diagnostics
from mreg_cli.diagnostics import Diagnostic, word_span
from mreg_cli.exceptions import ArgumentSplitBySeparator, InvalidFilterRegex
from mreg_cli.outputmanager import OutputManager

COMMAND_WITH_STANDALONE_FILTER = "policy list_atoms * | *dbora*"
COMMAND_WITH_EMBEDDED_SEPARATOR = (
    r"permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\.example\.com$ oracle"
)
EMBEDDED_SEPARATOR_WORD = r"^(db|cman)ora.*\.example\.com$"
EMBEDDED_SEPARATOR_FILTER = r"cman)ora.*\.example\.com$ oracle"
STANDALONE_FILTER_HEADLINE = "Unable to compile regex '*dbora*': nothing to repeat at position 0"


def spanned(command: str, span: tuple[int, int]) -> str:
    """Return the part of the command covered by span, so tests read as text, not indices."""
    start, end = span
    return command[start:end]


def test_doctests() -> None:
    """Ensure diagnostics module doctests are correct."""
    results = doctest.testmod(mreg_cli.diagnostics, verbose=False)
    assert results.attempted > 0
    assert results.failed == 0


def test_render_invalid_filter_regex() -> None:
    """Test underlining an invalid regex following a filter separator."""
    with pytest.raises(InvalidFilterRegex) as exc_info:
        OutputManager().get_filter(COMMAND_WITH_STANDALONE_FILTER)
    assert exc_info.value.diagnostic.render() == snapshot("""\
Unable to compile regex '*dbora*': nothing to repeat at position 0
policy list_atoms * | *dbora*
                      ^^^^^^^
                      └ This part is not a valid regular expression.\
""")


def test_render_argument_split_by_separator() -> None:
    """Test underlining an unquoted command argument unintentionally split by a filter separator `|`."""
    with pytest.raises(ArgumentSplitBySeparator) as exc_info:
        OutputManager().get_filter(COMMAND_WITH_EMBEDDED_SEPARATOR)
    assert exc_info.value.diagnostic.render() == snapshot("""\
Unable to compile regex 'cman)ora.*\\.example\\.com$ oracle'
permission label_add 192.168.0.0/24 oracle-group ^(db|cman)ora.*\\.example\\.com$ oracle
                                                 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                 └ Consider enclosing this part in quotes.\
""")


def test_word_span_covers_whole_word() -> None:
    """Test that word_span expands to whitespace on both sides."""
    command = "do_thing ^(yes|no)_thing$"
    span = word_span(command, command.index("|"))
    assert spanned(command, span) == "^(yes|no)_thing$"


def test_word_span_at_string_start() -> None:
    """Test word_span when the '|' word starts the command."""
    command = "| filter"
    span = word_span(command, command.index("|"))
    assert spanned(command, span) == "|"


@pytest.mark.parametrize("index", [-1, 8, 25, 99])
def test_word_span_outside_word_is_empty(index: int) -> None:
    """Test that word_span returns an empty span for whitespace or out-of-range indices."""
    assert word_span("do_thing ^(yes|no)_thing$", index) == (index, index)


@pytest.mark.parametrize("span", [(-5, 2), (99, 99), (5, 2), (-1, -1)])
def test_render_clamps_span_to_command(span: tuple[int, int]) -> None:
    """Test that a bad span never draws outside the command."""
    command = "ls a|b x"
    lines = Diagnostic("msg", command, span, "note").render().splitlines()
    underline, annotation = lines[2], lines[3]
    assert len(underline) <= len(command)
    assert annotation.index("└") <= len(command)


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        pytest.param("do_thing", ("do_thing", None, False), id="no_filter"),
        pytest.param("do_thing | foo", ("do_thing", "foo", False), id="simple"),
        pytest.param("do_thing |  a b  ", ("do_thing", "a b", False), id="internal_spaces"),
        pytest.param("do_thing | ! foo", ("do_thing", "foo", True), id="negated"),
        pytest.param("do_thing |!foo", ("do_thing", "foo", True), id="negated_glued"),
        pytest.param("do_thing |", ("do_thing", "", False), id="empty"),
        pytest.param("do_thing | !", ("do_thing", "", True), id="negation_marker_only"),
    ],
)
def test_get_filter_parses_filter(command: str, expected: tuple[str, str | None, bool]) -> None:
    """Test that get_filter splits off the pattern and negation marker."""
    cmd, filter_re, negate = OutputManager().get_filter(command)
    assert (cmd, filter_re.pattern if filter_re else None, negate) == expected


@pytest.mark.parametrize(
    ("command", "exc_type"),
    [
        pytest.param("do_thing | *x", InvalidFilterRegex, id="standalone"),
        pytest.param("| *x", InvalidFilterRegex, id="at_command_start"),
        pytest.param("do_thing |*x", ArgumentSplitBySeparator, id="glued_to_filter"),
        pytest.param("do_thing* |*x", ArgumentSplitBySeparator, id="glued_to_command"),
        pytest.param("do_thing ^(a|b)", ArgumentSplitBySeparator, id="embedded_in_regex"),
    ],
)
def test_get_filter_classifies_invalid_regex(command: str, exc_type: type[Exception]) -> None:
    """Test that a standalone '|' blames the regex, an embedded one blames the argument."""
    with pytest.raises(exc_type):
        OutputManager().get_filter(command)


def test_get_filter_multiword_filter_span() -> None:
    """Test that an invalid multi-word filter is underlined to the end, trailing spaces excluded."""
    command = "do_thing | cman)ora.* oracle  "
    with pytest.raises(InvalidFilterRegex) as exc_info:
        OutputManager().get_filter(command)
    assert spanned(command, exc_info.value.diagnostic.span) == "cman)ora.* oracle"


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
    assert spanned(diag.command, diag.span) == "*dbora*"
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
    assert spanned(diag.command, diag.span) == EMBEDDED_SEPARATOR_WORD
    assert diag.annotation == "Consider enclosing this part in quotes."


def test_get_filter_negated_invalid_filter_underlines_regex() -> None:
    """Test that a negated invalid filter underlines the regex, not the '!' marker."""
    with pytest.raises(InvalidFilterRegex) as exc_info:
        OutputManager().get_filter("policy list_atoms * | ! *dbora*")

    diag = exc_info.value.diagnostic
    assert diag is not None
    assert diag.message == STANDALONE_FILTER_HEADLINE
    assert spanned(diag.command, diag.span) == "*dbora*"
