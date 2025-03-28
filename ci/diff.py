from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
import urllib.parse
from enum import StrEnum
from typing import Any, Generator, Iterable, Literal, NamedTuple, Self, TypeAlias, overload

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt
from rich.table import Table

ProcessedCommand: TypeAlias = dict[str, Any]
UnprocessedCommand: TypeAlias = dict[str, Any]

console = Console(soft_wrap=True, highlight=False)
"""Stdout console used to print diffs."""

err_console = Console(stderr=True, highlight=False)
"""Stderr console used to print messages and errors."""

timestamp_pattern = re.compile(
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?|\d{4}-\d{2}-\d{2}"
)
datetime_str_pattern = re.compile(
    r"\b[A-Za-z]{3}\s[A-Za-z]{3}\s+([0-2]?[0-9]|3[0-1])\s([0-1]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\s[0-9]{4}\b"
)
serial_pattern = re.compile(r"\b[sS]erial:\s+\d+")
ipv4_pattern = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
ipv6_pattern = re.compile(r"\b([0-9a-fA-F]{1,4}::?){1,7}[0-9a-fA-F]{1,4}\b")
mac_pattern = re.compile(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b")

# Pattern matching strings starting with `"url": "/api/v1/` and ending with `"`
api_v1_pattern = re.compile(r'"url":\s*"/api/v1/.*?"')
# Pattern matching URLs where the final component is a number
# Defines 4 capture groups to be able to replace the number with a placeholder.
# Only matches the number if it is preceded by a `/` or `=`
# Does not match patterns containing `<IPv4>` and `<IPv6>` after `/api/v1/`.
api_v1_pattern_with_number = re.compile(
    r'("url":\s*"/api/v1/(?!.*?<(?:IPv6|IPv4)>).*?)([/=])(\d+)(")'
)


class DiffError(Exception):
    """Base class for diff errors."""


class CommandCountError(DiffError):
    """Exception raised when the number of commands in the two files is different."""

    def __init__(self, expected: int, result: int) -> None:  # noqa: D107
        self.expected = expected
        self.result = result
        super().__init__(
            f"Expected {expected} commands, got {result} commands. Diff must be resolved manually."
        )


DIFF_COLORS = {"-": "red", "+": "green"}


def fmt_line(line: str) -> str:
    """Format a single diff line with color."""
    line = escape(line)
    if line and (color := DIFF_COLORS.get(line[0], None)):
        return f"[{color}]{line}[/]"
    return line


def fmt_lines(lines: Iterable[str]) -> str:
    """Format diff lines."""
    return "".join(fmt_line(line) for line in lines)


DIFF_HEADER = f"{fmt_line('-expected')}, {fmt_line('+tested')}"


class Diff(NamedTuple):
    """A diff between two lists of strings."""

    number: int
    """The number of the diff."""

    diff: list[str]
    """The diff between the two lists of strings."""

    @property
    def renderable(self) -> Group:
        """Console renderable for the diff."""
        diff_lines = fmt_lines(self.diff)
        diff_title = f"\n[bold]#{self.number}[/]"
        return Group(diff_title, DIFF_HEADER, Panel(diff_lines, box=box.HORIZONTALS))

    @classmethod
    def from_lines(cls, number: int, expected: list[str], result: list[str]) -> Self:
        """Print a diff between two lists of strings."""
        lines = list(difflib.ndiff(expected, result))
        return cls(number, lines)

    def get_changed_lines(self) -> Iterable[str]:
        """Get lines with changes (added or removed)."""
        return (line for line in self.diff if line.startswith("+ ") or line.startswith("- "))

    def get_changes(self) -> str:
        """Get a formatted string of only the changes in the diff."""
        return "\n".join(fmt_line(line) for line in self.get_changed_lines())


class Choice(StrEnum):
    """Choices for diff review."""

    YES = "y"
    YES_TO_ALL = "Y"
    NO = "n"
    NO_TO_ALL = "N"

    @classmethod
    def as_string(cls) -> str:
        """Get a list of choice names as a string."""
        choices: list[str] = []
        for choice in cls:
            name = choice.name.capitalize().replace("_", " ")
            choices.append(name)
        return "/".join(choices)


def unquote_url(match: re.Match[str]) -> str:
    """Unquote URL encoded text in a /api/v1/ URL."""
    return urllib.parse.unquote(match.group(0))


def replace_url_id(match: re.Match[str]) -> str:
    """Replace the final number (ID) in a URL with a placeholder."""
    # match.group(1) contains the part before the separator (`"url": "/api/...`)
    # match.group(2) contains the separator (/ or =)
    # match.group(3) contains the number we want to replace
    # match.group(4) contains the closing double quote
    return f"{match.group(1)}{match.group(2)}<ID>{match.group(4)}"


def preprocess_json(s: str) -> str:
    """Preprocess JSON string for diffing. Replace non-deterministic values with placeholders."""
    # Replace all URL encoded text in /api/v1/ URLs with unquoted text
    # This lets us replace it down the line with our normal IPv{4,6} and MAC placeholders
    # Must be done _before_ all other replacements
    s = api_v1_pattern.sub(unquote_url, s)

    # Replace all non-deterministic values with placeholders
    s = timestamp_pattern.sub("<TIME>", s)
    s = datetime_str_pattern.sub("<DATETIME>", s)
    s = serial_pattern.sub("Serial: <NUMBER>", s)
    s = mac_pattern.sub("<macaddress>", s)
    s = ipv4_pattern.sub("<IPv4>", s)
    s = ipv6_pattern.sub("<IPv6>", s)

    # Replace all IDs in URLs with a placeholder
    # Must be done _after_ all other replacements
    s = api_v1_pattern_with_number.sub(replace_url_id, s)

    s = re.sub(
        r"\s+", " ", s
    )  # replace all whitespace with one space, so the diff doesn't complain about different lengths
    return s


@overload
def load_commands(file: str, *, preprocess: Literal[False]) -> list[UnprocessedCommand]: ...


@overload
def load_commands(file: str, *, preprocess: Literal[True]) -> list[ProcessedCommand]: ...


def load_commands(
    file: str, *, preprocess: bool = True
) -> list[ProcessedCommand] | list[UnprocessedCommand]:
    """Load JSON commands from a test suite log file."""
    with open(file, "r") as f:
        s = f.read()
    if preprocess:
        s = preprocess_json(s)
    data = json.loads(s)
    commands: list[dict[str, Any]] = []
    for obj in data:
        if "command" in obj:
            commands.append(obj)
    return commands


class TestCommand(NamedTuple):
    """A single command from a test suite log."""

    command: ProcessedCommand
    """Processed command data, with placeholders for non-deterministic values."""

    original: UnprocessedCommand
    """Unprocessed original command data."""


class TestSuiteResult:
    """The results of a test suite run."""

    def __init__(self, file: str) -> None:
        self.file = file
        self.commands = load_commands(file, preprocess=True)
        self.commands_original = load_commands(file, preprocess=False)

    def iterate(
        self, other: TestSuiteResult
    ) -> Generator[tuple[TestCommand, TestCommand], None, None]:
        """Iterate over commands from two TestSuiteResult objects."""
        for command, other_command in zip(self, other):
            yield command, other_command

    def __iter__(self) -> Generator[TestCommand, None, None]:
        """Iterate over the commands and their original form."""
        for i, command in enumerate(self.commands):
            yield TestCommand(command, self.commands_original[i])

    def ensure_comparable(self, other: TestSuiteResult) -> None:
        """Check if self and other have the same number of commands."""
        if len(self.commands) != len(other.commands):
            raise CommandCountError(len(self.commands), len(other.commands))
        for obj in [self, other]:
            if len(obj.commands) != len(obj.commands_original):
                raise DiffError(
                    f"{obj.file} has different number of commands after preprocessing. "
                    f"Before: {len(obj.commands_original)}, After: {len(obj.commands)}"
                )


class CommandDiff(NamedTuple):
    """(un)resolved diff between two test suite results."""

    expected: UnprocessedCommand
    """The command that was expected."""

    result: UnprocessedCommand
    """The command that was actually run."""

    diff: Diff
    """The diff between the two commands."""

    def get_command(self) -> str:
        """Get the name of the command that was run."""
        return self.expected.get("command", self.result.get("command", "<unknown>"))


class CommandDiffer:
    """Diffs the results (JSON output) of commands from two files."""

    def __init__(self, file1: str, file2: str, review: bool = False) -> None:
        """Initialize command differ with files to diff."""
        self.file1 = file1
        self.file2 = file2
        self.review = review

        # Load files
        self.expected = TestSuiteResult(file1)
        self.result = TestSuiteResult(file2)

        self.diff_resolved: list[CommandDiff] = []
        self.diff_unresolved: list[CommandDiff] = []

    def diff(self) -> None:
        """Diff the two files."""
        self.diff_executed_commands()
        self.diff_command_results()

    def diff_executed_commands(self) -> None:
        """Diff the number and order of commands in the two files."""
        differ = difflib.Differ()

        expected_commands = [c["command"] for c in self.expected.commands]
        result_commands = [c["command"] for c in self.result.commands]

        diff = differ.compare(expected_commands, result_commands)
        differences = [line for line in diff if line.startswith("-") or line.startswith("+")]
        if differences:
            err_console.print(
                "Diff between what commands were run in the recorded result and the current testsuite:"
            )
            for line in differences:
                err_console.print(fmt_line(line))
            raise CommandCountError(len(expected_commands), len(result_commands))

    def log_unresolved_diff(self, expected: TestCommand, result: TestCommand, diff: Diff) -> None:
        """Log an unresolved diff between two commands."""
        self.diff_unresolved.append(CommandDiff(expected.original, result.original, diff))

    def log_resolved_diff(self, expected: TestCommand, result: TestCommand, diff: Diff) -> None:
        """Log a resolved diff between two commands."""
        self.diff_resolved.append(CommandDiff(expected.original, result.original, diff))

    def diff_command_results(self) -> None:
        """Diff the contents of each command in the two files."""
        # NOTE: Only used in review mode
        new_testsuite_results: list[dict[str, Any]] = []

        # TODO: Normalize results:
        #       * Add placeholders for removed commands
        #       * Add placeholders for added commands
        #       The difficulty comes from determining WHERE to insert placeholders
        #       For added difficulty, if we repeat the same command, how
        #       do we know which one to add the placeholder for, etc.
        diff_n = 0  # Number of current diff being resolved
        yes_all = False
        no_all = False

        # Check if everything is in order before we start iterating
        self.expected.ensure_comparable(self.result)

        for expected, result in self.expected.iterate(self.result):
            expected_lines = json.dumps(expected.command, indent=2).splitlines(keepends=True)
            result_lines = json.dumps(result.command, indent=2).splitlines(keepends=True)

            if expected_lines != result_lines:
                diff_n += 1
                d = Diff.from_lines(diff_n, expected_lines, result_lines)
                if not self.review:
                    self.log_unresolved_diff(expected, result, d)
                    console.print(d.renderable)
                    continue  # Nothing more to do for this command

                if no_all:
                    choice = Choice.NO
                elif yes_all:
                    choice = Choice.YES
                else:
                    console.print(d.renderable)
                    choice = Prompt.ask(
                        f"Accept change #{diff_n}? ({Choice.as_string()})",
                        choices=list(Choice),
                        default=Choice.YES,
                    )
                    if choice == Choice.YES_TO_ALL:
                        yes_all = True
                        choice = Choice.YES
                    elif choice == Choice.NO_TO_ALL:
                        no_all = True
                        choice = Choice.NO

                if choice == Choice.YES:
                    # Accept new line
                    new_testsuite_results.append(result.original)
                    self.log_resolved_diff(expected, result, d)
                else:
                    # Keep old line
                    new_testsuite_results.append(expected.original)
                    self.log_unresolved_diff(expected, result, d)
            else:
                # No diff, keep old line
                new_testsuite_results.append(expected.original)

        # Only write back changes if we are in review mode and there are changes
        if self.review and len(self.diff_resolved) > 0:
            # Write accepted changes back to file1
            with open(self.file1, "w") as f:
                json.dump(new_testsuite_results, f, indent=2)
            err_console.print(f"Wrote accepted changes back to {self.file1}")


def print_diff_summary(diffs: list[CommandDiff], title: str) -> None:
    """Print a summary of diffs."""
    if diffs:
        tbl = Table(
            "Command",
            "Diff",
            title=title,
            show_header=True,
            show_lines=True,
            expand=True,
        )
        for cmd in diffs:
            tbl.add_row(
                cmd.get_command(),
                cmd.diff.get_changes(),
            )
        err_console.print(tbl)


def main() -> None:
    """Compare two JSON files."""
    parser = argparse.ArgumentParser(prog="diff.py")
    parser.add_argument("file1", help="First JSON file to compare")
    parser.add_argument("file2", help="Second JSON file to compare")
    parser.add_argument(
        "--review", "-r", action="store_true", help="Review each diff", default=False
    )
    args = parser.parse_args()

    file1: str = args.file1
    file2: str = args.file2
    review: bool = args.review

    differ = CommandDiffer(file1, file2, review=review)

    try:
        differ.diff()
    except DiffError as e:
        err_console.print(f"[red]ERROR: {e}[/]")
        sys.exit(2)

    # We can print a combination of messages here.
    # I.e. resolved msg followed by unresolved msg with non-zero exit code
    resolved = differ.diff_resolved
    unresolved = differ.diff_unresolved
    print_diff_summary(resolved, "[green italic]Resolved diffs[/]")
    print_diff_summary(unresolved, "[red italic]Unresolved diffs[/]")
    if resolved:
        err_console.print(f"[green]Resolved {len(resolved)} diffs between {file1} and {file2}[/]")
    if unresolved:  # non-zero exit code if unresolved diffs
        err_console.print(
            f"[red]{len(unresolved)} unresolved diffs between {file1} and {file2}.[/]"
        )
        sys.exit(1)
    if not resolved and not unresolved:  # no diffs found
        err_console.print(f"No differences found between {file1} and {file2}")


if __name__ == "__main__":
    main()
