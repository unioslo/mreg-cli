"""Compiler-style diagnostics for invalidly formatted commands.

A diagnostic couples a headline message to the exact span of the command that
caused it, plus an annotation displayed under the underlined span.

No attribution happens in this module; the raised exception contains
the "ground truth", i.e. details about what caused the exception, which
this module in turn uses to determine the appropriate diagnostic message and span.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import re


@dataclass(frozen=True)
class Diagnostic:
    """A message tied to a span of the issued command, with an annotation.

    Attributes:
        message: Headline displayed above the command.
        command: The issued command; span indexes into it.
        span: (start, end) of the underlined part — start inclusive, end exclusive.
        annotation: Text displayed under the underline.

    """

    message: str
    command: str
    span: tuple[int, int]
    annotation: str

    # Characters used when rendering the underline and the annotation.
    CHAR_UNDERLINE = "^"
    CHAR_SUGGESTION = "└"

    def render(self) -> str:
        """Render headline, command, underline and annotation (4 lines, no trailing newline).

        :returns: The rendered diagnostic.
        """
        start, end = self.span
        offset = " " * start
        lines = [
            self.message,
            self.command,
            offset + self.CHAR_UNDERLINE * (end - start),
            offset + self.CHAR_SUGGESTION + " " + self.annotation,
        ]
        return "\n".join(lines)


def is_standalone_separator(command: str, split_index: int) -> bool:
    """Check whether the '|' at split_index is a word of its own in the command.

    True if and only if the character at `split_index` is `'|'` and it is
    surrounded by whitespace or sits at the start or end of the command.

    :param str command: The command to inspect.
    :param int split_index: The index of the '|' separator in the command.

    :returns: True if the '|' is a standalone separator word.

    :examples:
        >>> is_standalone_separator("do_thing | filter", 9)
        True
        >>> is_standalone_separator("do_thing ^(yes|no)_thing$", 14)
        False
        >>> is_standalone_separator("do_thing |*dbora*", 9)
        False
        >>> is_standalone_separator("| filter", 0)
        True
        >>> is_standalone_separator("do_thing |", 9)
        True
        >>> is_standalone_separator("do_thing | filter", 0)
        False
    """
    if not 0 <= split_index < len(command) or command[split_index] != "|":
        return False
    before_ok = split_index == 0 or command[split_index - 1].isspace()
    after_ok = split_index == len(command) - 1 or command[split_index + 1].isspace()
    return before_ok and after_ok


def word_span(command: str, index: int) -> tuple[int, int]:
    """Get the span of the whitespace-delimited word containing index.

    Expands from `index` to whitespace on both sides, so the span covers the
    whole word containing the '|' at `index`.

    :param str command: The command to inspect.
    :param int index: The index of the '|' separator in the command.

    :returns: Tuple of the word's start (inclusive) and end (exclusive) index.

    :raises ValueError: If index is out of range for the command.

    :examples:
        >>> word_span("do_thing ^(yes|no)_thing$", 14)
        (9, 25)
        >>> word_span("| filter", 0)
        (0, 1)
        >>> word_span("do_thing |*dbora*", 9)
        (9, 17)
    """
    if not 0 <= index < len(command):
        raise ValueError(f"index {index} out of range for command of length {len(command)}")
    start = index
    end = index + 1
    while start > 0 and not command[start - 1].isspace():
        start -= 1
    while end < len(command) and not command[end].isspace():
        end += 1
    return (start, end)


def tail_span(command: str, split_index: int) -> tuple[int, int]:
    """Get the span of the filter that follows the '|' separator.

    Optional leading negation marker ('!') is skipped.

    :param str command: The command to inspect.
    :param int split_index: The index of the '|' separator in the command.

    :returns: Tuple of the filter's start (inclusive) and end (exclusive) index.

    :raises ValueError: If split_index is out of range, or the filter is empty.
        The latter is a documented precondition: the helper is only called when
        the filter failed to compile, which implies a non-empty filter.

    :examples:
        >>> tail_span("do_thing | ^(yes|no)_thing$", 9)
        (11, 27)
        >>> tail_span("do_thing | cman)ora.* oracle", 9)
        (11, 28)
        >>> tail_span("do_thing | ! *dbora*", 9)
        (13, 20)
        >>> tail_span("do_thing |", 9)
        Traceback (most recent call last):
            ...
        ValueError: empty filter after separator at index 9
    """
    if not 0 <= split_index < len(command):
        raise ValueError(
            f"split index {split_index} out of range for command of length {len(command)}"
        )
    start = split_index + 1
    end = len(command)
    while start < end and command[start].isspace():
        start += 1
    while end > start and command[end - 1].isspace():
        end -= 1
    # Mirror get_filter: an optional leading '!' negation marker is not part
    # of the compiled regex.
    if start < end and command[start] == "!":
        start += 1
        while start < end and command[start].isspace():
            start += 1
    if start >= end:
        raise ValueError(f"empty filter after separator at index {split_index}")
    return (start, end)


def invalid_filter_regex(
    command: str, split_index: int, filter_str: str, error: re.error
) -> Diagnostic:
    """Create a diagnostic for an invalid regex following a filter separator (`|`).

    :param str command: The command the filter was part of.
    :param int split_index: The index of the '|' separator in the command.
    :param str filter_str: The filter string that failed to compile.
    :param re.error error: The regex compilation error; its reason is appended to the headline.

    :returns: A diagnostic pointing at the filter that failed to compile.
    """
    return Diagnostic(
        message=f"Unable to compile regex '{filter_str}': {error}",
        command=command,
        span=tail_span(command, split_index),
        annotation="This part is not a valid regular expression.",
    )


def argument_split_by_separator(command: str, split_index: int, filter_str: str) -> Diagnostic:
    """Create a diagnostic for an unquoted argument containing a filter separator (`|`).

    :param str command: The command that was split.
    :param int split_index: The index of the '|' separator in the command.
    :param str filter_str: The substring of the command following the '|' separator.

    :returns: A diagnostic pointing at the argument word containing the '|'.
    """
    return Diagnostic(
        message=f"Unable to compile regex '{filter_str}'",
        command=command,
        span=word_span(command, split_index),
        annotation="Consider enclosing this part in quotes.",
    )
