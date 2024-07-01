from __future__ import annotations

import argparse
import difflib
import json
import re
import sys
from enum import StrEnum
from itertools import zip_longest
from typing import Any, Iterable

from rich import box
from rich.console import Console, Group
from rich.markup import escape
from rich.panel import Panel
from rich.prompt import Prompt

console = Console(soft_wrap=True, highlight=False)
err_console = Console(stderr=True)

timestamp_pattern = re.compile(
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?|\d{4}-\d{2}-\d{2}"
)
datetime_str_pattern = re.compile(
    r"\b[A-Za-z]{3}\s[A-Za-z]{3}\s+([0-2]?[0-9]|3[0-1])\s([0-1]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\s[0-9]{4}\b"
)
serial_pattern = re.compile(r"\b[sS]erial:\s+\d+")
ipv4_pattern = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
ipv6_pattern = re.compile(r"\b([0-9a-fA-F]{1,4}::?){1,7}[0-9a-fA-F]{1,4}\b")


class DiffError(Exception):
    """Base class for diff errors."""


class CommandCountError(DiffError):
    """Exception raised when the number of commands in the two files is different."""

    def __init__(self, expected: int, result: int) -> None:  # noqa: D107
        self.expected = expected
        self.result = result
        super().__init__(
            f"Expected {expected} commands, got {result} commands. Resolve the diff manually."
        )


class UnresolvedDiffError(DiffError):
    """Exception raised when the commands in the two files are different."""

    def __init__(self, file1: str, file2: str, n_diffs: int) -> None:  # noqa: D107
        super().__init__(f"{n_diffs} unresolved diff(s) between {file1} and {file2}.")


def group_objects(json_file_path: str) -> list[dict[str, Any]]:
    """Group objects in a JSON file by a specific criterion.

    :param json_file_path: Path to the JSON file.
    :returns: A list of grouped objects.
    """
    with open(json_file_path, "r") as f:
        s = f.read()
        s = timestamp_pattern.sub("<TIME>", s)
        s = datetime_str_pattern.sub("<TIME>", s)
        s = serial_pattern.sub("Serial: <NUMBER>", s)
        s = ipv4_pattern.sub("<IPv4>", s)
        s = ipv6_pattern.sub("<IPv6>", s)
        s = re.sub(
            r"\s+", " ", s
        )  # replace all whitespace with one space, so the diff doesn't complain about different lengths
        data = json.loads(s)

    commands: list[dict[str, Any]] = []
    for obj in data:
        if "command" in obj:
            commands.append(obj)
    return commands


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


def get_diff(expected: list[str], result: list[str]) -> Group:
    """Print a diff between two lists of strings."""
    gen = difflib.ndiff(expected, result)
    lines = fmt_lines(gen)
    return Group(DIFF_HEADER, Panel(lines, box=box.HORIZONTALS))


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


class CommandDiffer:
    """Diffs the results (JSON output) of commands from two files."""

    def __init__(self, file1: str, file2: str, review: bool = False) -> None:
        """Initialize command differ with files to diff."""
        self.file1 = file1
        self.file2 = file2
        self.review = review

        # Load files
        self.expected = group_objects(self.file1)
        self.result = group_objects(self.file2)
        self.n_diffs = 0

    def diff(self) -> None:
        """Diff the two files."""
        self.diff_executed_commands()
        self.diff_command_results()

    def diff_executed_commands(self) -> None:
        """Diff the number and order of commands in the two files."""
        differ = difflib.Differ()

        expected_commands = [c["command"] for c in self.expected]
        result_commands = [c["command"] for c in self.result]

        diff = differ.compare(expected_commands, result_commands)
        differences = [line for line in diff if line.startswith("-") or line.startswith("+")]
        if differences:
            console.print(
                "Diff between what commands were run in the recorded result and the current testsuite:"
            )
            for line in differences:
                console.print(fmt_line(line))
            raise CommandCountError(len(expected_commands), len(result_commands))

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
        n_diffs = 0
        yes_all = False
        no_all = False

        fill: dict[str, Any] = {}
        for expected, result in zip_longest(self.expected, self.result, fillvalue=fill):
            # TODO: Compare result and expected before splitting into lines
            #       That SHOULD yield the same results, but we need to test it
            expected_lines = json.dumps(expected, indent=2).splitlines(keepends=True)
            result_lines = json.dumps(result, indent=2).splitlines(keepends=True)
            if expected_lines != result_lines:
                d = get_diff(expected_lines, result_lines)
                if not self.review:
                    n_diffs += 1
                    console.print(d)
                    continue  # Nothing more to do for this command

                if no_all:
                    choice = Choice.NO
                elif yes_all:
                    choice = Choice.YES
                else:
                    console.print(d)
                    choice = Prompt.ask(
                        f"Accept change? ({Choice.as_string()})",
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
                    new_testsuite_results.append(result)
                else:
                    # Keep old line
                    new_testsuite_results.append(expected)
                    n_diffs += 1
            else:
                # No diff, keep new line
                new_testsuite_results.append(result)

        # Only write back changes if we are in review mode
        if self.review and (self.result != new_testsuite_results):
            # Write accepted changes back to file1
            with open(self.file1, "w") as f:
                json.dump(new_testsuite_results, f, indent=2)
            err_console.print(f"Wrote accepted changes back to {self.file1}")

        if n_diffs:
            raise UnresolvedDiffError(self.file1, self.file2, n_diffs)


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
        sys.exit(1)
    else:
        err_console.print(f"No differences found between {file1} and {file2}")


if __name__ == "__main__":
    main()
