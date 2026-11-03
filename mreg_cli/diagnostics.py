"""Compiler-style diagnostics for invalidly formatted commands.

A diagnostic couples a headline message to the exact span of the command that
caused it, plus an annotation displayed under the underlined span.

Spans are computed by the code that parses the command (the single source of
truth); this module only renders them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


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

        The span is clamped to the command, so a bad span can never break rendering.

        :returns: The rendered diagnostic.
        """
        start, end = self.span
        start = max(0, min(start, len(self.command)))
        end = max(start, min(end, len(self.command)))
        offset = " " * start
        lines = [
            self.message,
            self.command,
            offset + self.CHAR_UNDERLINE * (end - start),
            offset + self.CHAR_SUGGESTION + " " + self.annotation,
        ]
        return "\n".join(lines)


def word_span(command: str, index: int) -> tuple[int, int]:
    """Get the span of the whitespace-delimited word containing index.

    :param str command: The command to inspect.
    Never raises: used while reporting errors, so it must not create new ones.

    :param str command: The command to inspect.
    :param int index: Index of a character in the command.

    :returns: Tuple of the word's start (inclusive) and end (exclusive) index,
        or the empty span (index, index) if index is not inside a word.

    :examples:
        >>> word_span("do_thing ^(yes|no)_thing$", 14)
        (9, 25)
        >>> word_span("| filter", 0)
        (0, 1)
        >>> word_span("do_thing |*dbora*", 9)
        (9, 17)
    """
    for match in re.finditer(r"\S+", command):
        if match.start() <= index < match.end():
            return match.span()
    return (index, index)  # dummy span for out-of-word indices
