from __future__ import annotations

import difflib
import json
import re
import sys
from typing import Any, Dict, Iterable, List

from rich.console import Console
from rich.markup import escape

console = Console(soft_wrap=True, highlight=False)

timestamp_pattern = re.compile(
    r"\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?|\d{4}-\d{2}-\d{2}"
)
datetime_str_pattern = re.compile(
    r"\b[A-Za-z]{3}\s[A-Za-z]{3}\s+([0-2]?[0-9]|3[0-1])\s([0-1]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\s[0-9]{4}\b"
)
# datetime_str_pattern = re.compile(
#     r"\b(Sun|Mon|Tue|Wed|Thu|Fri|Sat)\s(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s([0-2]?[0-9]|3[0-1])\s([0-1]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])\s[0-9]{4}\b"
# )
serial_pattern = re.compile(r"\b[sS]erial:\s+\d+")
ipv4_pattern = re.compile(r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}")
ipv6_pattern = re.compile(r"\b([0-9a-fA-F]{1,4}::?){1,7}[0-9a-fA-F]{1,4}\b")

# Keeping this code in case we need to revert back to it:
#
# def replace_timestamps_and_more(obj: Any) -> Any:
#     """Recursively replace timestamp values in a JSON object.
#
#     :param obj: A JSON object (dict, list, or primitive type).
#     :returns: A new object with timestamps replaced.
#     """
#     if isinstance(obj, dict):
#         #return {ipv4_pattern.sub("<IPv4>",k): replace_timestamps_and_more(v) for k, v in obj.items()}
#         newdict = {}
#         for k, v in obj.items():
#             # some places, ip addresses are used as keys
#             k = ipv4_pattern.sub("<IPv4>",k)
#             k = ipv6_pattern.sub("<IPv6>",k)
#             v = replace_timestamps_and_more(v)
#             newdict[k] = v
#         return newdict
#     elif isinstance(obj, list):
#         return [replace_timestamps_and_more(elem) for elem in obj]
#     elif isinstance(obj, str):
#         obj = timestamp_pattern.sub("<TIME>", obj)
#         obj = datetime_str_pattern.sub("<TIME>", obj)
#         obj = serial_pattern.sub("Serial: <NUMBER>", obj)
#         obj = ipv4_pattern.sub("<IPv4>", obj)
#         obj = ipv6_pattern.sub("<IPv6>", obj)
#         return obj
#     return obj


def group_objects(json_file_path: str) -> List[List[Dict[str, Any]]]:
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

    # data = [replace_timestamps_and_more(obj) for obj in data]

    grouped_objects = []
    temp = []

    for obj in data:
        if "command" in obj:
            if temp:
                grouped_objects.append(temp)
                temp = []
        temp.append(obj)

    if temp:
        grouped_objects.append(temp)

    return grouped_objects


COLOR_MAP = {"-": "red", "+": "green"}


def fmt_line(line: str) -> str:
    """Format a single diff line with color."""
    line = escape(line)
    if line and (color := COLOR_MAP.get(line[0], None)):
        return f"[{color}]{line}[/]"
    return line


def fmt_lines(lines: Iterable[str]) -> str:
    """Format diff lines."""
    return "".join(fmt_line(line) for line in lines)


def main() -> None:
    """Compare two JSON files."""
    if len(sys.argv) != 3:
        console.print("Usage: diff.py <file1> <file2>")
        sys.exit(1)

    expected = group_objects(sys.argv[1])
    result = group_objects(sys.argv[2])

    # Verify that the list of commands is the same
    cmdlist1 = []
    cmdlist2 = []
    for a in expected:
        cmdlist1.append(a[0]["command"].rstrip())
    for a in result:
        cmdlist2.append(a[0]["command"].rstrip())
    differ = difflib.Differ()
    diff = differ.compare(cmdlist1, cmdlist2)
    differences = [line for line in diff if line.startswith("-") or line.startswith("+")]
    if differences:
        console.print(
            "Diff between what commands were run in the recorded result and the current testsuite:"
        )
        for line in differences:
            console.print(line)
        sys.exit(1)

    # For each command, verify that the http calls and output is the same
    has_diff = False
    for i in range(len(expected)):
        cmd = escape(expected[i][0]["command"].rstrip())
        cmd2 = escape(result[i][0]["command"].rstrip())
        if cmd != cmd2:
            # This should never happen here, because it would get caught above
            console.print(f"Expected command: {cmd}\nActual command: {cmd2}")
            sys.exit(1)

        s1 = json.dumps(expected[i], indent=4).splitlines(keepends=True)
        s2 = json.dumps(result[i], indent=4).splitlines(keepends=True)
        if s1 != s2:
            has_diff = True
            console.print("=" * 72)
            console.print(f"Command: {cmd}        {fmt_line('-expected')}, {fmt_line('+tested')}")
            console.print("=" * 72)
            gen = difflib.ndiff(s1, s2)
            lines = fmt_lines(gen)
            console.print(lines, end="", sep="")
            console.print("\n")  # 2 newlines

    if has_diff:
        sys.exit(1)


if __name__ == "__main__":
    main()
