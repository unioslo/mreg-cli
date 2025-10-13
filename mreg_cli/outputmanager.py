"""Output management for mreg_cli.

This is a singleton class that manages the output for the CLI. It stores the
output lines and formats them for display. It also manages the filter for the
command.
"""

from __future__ import annotations

import atexit
import datetime
import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Literal, overload
from urllib.parse import urlencode, urlparse

import requests
from pydantic import BaseModel

from mreg_cli.errorbuilder import build_error_message
from mreg_cli.exceptions import CliError, FileError
from mreg_cli.types import Json, JsonMapping, RecordingEntry, TimeInfo

logger = logging.getLogger(__name__)


@overload
def find_char_outside_quotes(
    line: str, target_char: str, return_position: Literal[True]
) -> int: ...


@overload
def find_char_outside_quotes(
    line: str, target_char: str, return_position: Literal[False]
) -> str: ...


def find_char_outside_quotes(
    line: str, target_char: str, return_position: bool = False
) -> str | int:
    """Find a specified character in a line outside of quoted sections.

    :param line: The line of text to process.
    :param target_char: The character to find.
    :param return_position: If True, return the position of the character;
                            If False, return the line up to the character.
    :return: The position of the character or the line up to the character.
    """
    in_quotes = False
    current_quote = None

    for i, char in enumerate(line):
        if char in ["'", '"']:
            if in_quotes and char == current_quote:
                in_quotes = False
                current_quote = None
            elif not in_quotes:
                in_quotes = True
                current_quote = char
        elif char == target_char and not in_quotes:
            return i if return_position else line[:i]

    return -1 if return_position else line


def remove_comments(line: str) -> str:
    """Remove everything after "#" in line of text.

    Note: If the "#" is within a quoted string, it is not deemed to start a comment.

    :param line: The line of text to process.
    :return: The line with comments removed.
    """
    return find_char_outside_quotes(line, "#", False).rstrip(" ")


def remove_dict_key_recursive(obj: Json, key: str) -> None:
    """Remove a key from a dict or list of dicts, recursively.

    This is a destructive operation, and will modify the object in place.
    """
    if isinstance(obj, list):
        for elem in obj:
            remove_dict_key_recursive(elem, key)
        return
    elif isinstance(obj, dict):
        try:
            del obj[key]
        except KeyError:
            pass
        for other_value in obj.values():
            remove_dict_key_recursive(other_value, key)


def urlpath(url: str, params: JsonMapping) -> str:
    """Return the path and query string of a URL."""
    if params:
        url = f"{url}?{urlencode(params)}"
    up = urlparse(url)
    # Compare to empty string to avoid being tripped up by strings having
    # false-like values (0, False, etc)
    if up.query != "":
        return up.path + "?" + up.query
    else:
        return up.path


class OutputManager:
    """Manages and formats output for display.

    This is a singleton class to retain context between calls. It is initiated
    and cleared in the main function of the CLI, all other calls should only
    add lines to the output via add_line(), add_formatted_line(), or
    add_formatted_line_with_source(),
    """

    _instance = None

    COMMANDS_NOT_TO_RECORD = ["recording", "quit", "exit", "source"]
    KEYS_NOT_TO_RECORD = [
        "id",
        "serialno",
        "create_date",
    ]

    def __new__(cls):
        """Create a new instance of the class, or return the existing one."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.clear()
            cls._instance.recording_clear()

        return cls._instance

    def clear(self) -> None:
        """Clear the object."""
        self._output: list[str] = []
        self._filter_re: re.Pattern[str] | None = None
        self._filter_negate: bool = False
        self._command_executed: str = ""
        self._command_issued: str = ""

        self._ok: list[str] = []  # This is typically commands that went OK but returned no content
        self._warnings: list[str] = []
        self._errors: list[str] = []

        self._api_requests: list[dict[str, Any]] = []

        self._time_started: datetime.datetime = datetime.datetime.now()

    def recording_clear(self) -> None:
        """Clear the recording data."""
        self._recorded_data: list[RecordingEntry] = []
        self._recording: bool = False
        self._file: Path | None = None
        self._record_timestamps: bool = True

    def record_timestamps(self, state: bool) -> None:
        """Set whether to record timestamps in the recording.

        :param state: True to record timestamps, False to not record timestamps.
        """
        self._record_timestamps = state

    def recording_start(self, file: Path) -> None:
        """Declare intent to start recording to the given filename.

        Note: The file will be overwritten if it exists.

        :param filename: The filename to record to.
        """
        # Check that we actually have a file
        if file.exists() and file.is_dir():
            raise FileError(f"Recording file cannot be a directory: {file}")

        # Check that we can write to the file
        try:
            file.write_text("")  # checks write access and wipes file
        except OSError as exc:
            raise FileError(f"Unable open recording file for writing: {file}") from exc

        self._recording = True
        self._file = file

        atexit.register(self.recording_stop)

    def recording_stop(self) -> None:
        """Stop the recording and save the recording to the file.

        Returns gracefully if recording is not active.
        """
        if not self.recording_active() or not self._file:
            return

        self._file.write_text(json.dumps(self._recorded_data, indent=2))

        self.recording_clear()

    def recording_entry(self) -> RecordingEntry:
        """Create a recording entry."""
        now = datetime.datetime.now()
        start = self._time_started

        time: TimeInfo = {
            "timestamp": start.isoformat(sep=" ", timespec="seconds"),
            "timestamp_as_epoch": int(start.timestamp()),
            "runtime_in_ms": int((now - start).total_seconds() * 1000),
        }

        return {
            "command": self._command_executed,
            "command_filter": self._filter_re.pattern if self._filter_re else None,
            "command_filter_negate": self._filter_negate,
            "command_issued": self._command_issued,
            "ok": self._ok,
            "warning": self._warnings,
            "error": self._errors,
            "output": self.filtered_output(),
            "api_requests": self._api_requests,
            "time": time if self._record_timestamps else None,
        }

    def add_warning(self, msg: str) -> None:
        """Add a warning event to the output.

        :param msg: The warning message.
        """
        self._warnings.append(msg)

    def add_error(self, msg: str) -> None:
        """Add an error event to the output.

        :param msg: The error message.
        """
        self._errors.append(msg)

    def add_ok(self, msg: str) -> None:
        """Add an OK event to the output.

        :param msg: The ok message.
        """
        self._ok.append(msg)

    def recording_active(self) -> bool:
        """Return True if recording is active."""
        return self._recording

    def recording_filename(self) -> Path | None:
        """Return the filename being recorded to.

        Return gracefully if recording is not active.
        """
        if not self.recording_active():
            return None
        return self._file

    def recording_output(self) -> None:
        """Record the output, if recording is active."""
        command = self._command_executed
        # Note that we may record commands without output as they may have
        # warnings or errors.
        if not command or not self.recording_active():
            return

        if any(command.startswith(cmd) for cmd in self.COMMANDS_NOT_TO_RECORD):
            return

        self._recorded_data.append(self.recording_entry())

    def recording_request(
        self,
        method: str,
        url: str,
        params: JsonMapping,
        data: dict[str, Any],
        result: requests.Response,
    ) -> None:
        """Record a request, if recording is active."""
        if not self.recording_active():
            return
        ret_dict: dict[str, Any] = {
            "method": method.upper(),
            "url": urlpath(url, params),
            "data": data,
            "status": result.status_code,
        }
        try:
            obj = result.json()
            for key in self.KEYS_NOT_TO_RECORD:
                remove_dict_key_recursive(obj, key)
            ret_dict["response"] = obj
        except requests.JSONDecodeError:
            s = result.content.decode("utf-8").strip()
            # Compare to empty string to avoid being tripped up by strings having
            # false-like values (0, False, etc)
            if s != "":
                ret_dict["response"] = s
        self._api_requests.append(ret_dict)

    def has_output(self) -> bool:
        """Return True if there is output to display."""
        return len(self._output) > 0

    def from_command(self, command: str) -> str:
        """Add the command that generated the output.

        Also records the command if recording is active.

        :param command: The command to add.
        :raises CliError: If the command is invalid.
        :return: The cleaned command, devoid of filters and other noise.
        """
        logger.debug(f"From command: {command}")
        self._command_issued = command.rstrip()
        self._command_executed, self._filter_re, self._filter_negate = self.get_filter(
            remove_comments(self._command_issued)
        )
        logger.info(f"From command (filtered): {self._command_executed}")
        return self._command_executed

    def add_line(self, line: str) -> None:
        """Add a line to the output.

        :param line: The line to add.
        """
        logger.debug(f"Adding line: {line}")
        self._output.append(line)

    def add_formatted_line(self, key: str, value: str, padding: int = 14) -> None:
        """Format and add a key-value pair as a line.

        :param key: The key or label.
        :param value: The value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2}".format(padding, key, value)
        self.add_line(formatted_line)

    def add_formatted_line_with_source(
        self, key: str, value: str, source: str = "", padding: int = 14
    ) -> None:
        """Format and adds a key-value pair as a line with a source.

        :param key: The key or label.
        :param value: The value.
        :param source: The source of the value.
        :param padding: The padding for the key.
        """
        formatted_line = "{1:<{0}} {2:<{0}} {3}".format(padding, key, value, source)
        self.add_line(formatted_line)

    def _find_split_index(self, command: str) -> int:
        """Find the index to split the command for filtering, outside of quoted sections.

        :param command: The command string to be processed.
        :return: The index at which to split the command, or -1 if not found.
        """
        return find_char_outside_quotes(command, "|", True)

    # We want to use re.Pattern as the type here, but python 3.6 and older re-modules
    # don't have that type. So we use Any instead.
    def get_filter(self, command: str) -> tuple[str, Any, bool]:
        """Return the filter for the output.

        Parses the command string and extracts a filter if present, taking into
        account both single and double quoted strings to avoid incorrect
        splitting.

        :param command: The command to parse for the filter.
        :raises CliError: If the filter is invalid.
        :return: The command, the filter, and whether it is a negated filter.
        """
        negate = False
        filter_re = None

        if command:
            split_index = self._find_split_index(command)

            if split_index != -1:
                command_issued = command
                filter_str = command[split_index + 1 :].strip()
                command = command[:split_index].strip()

                if filter_str.startswith("!"):
                    negate = True
                    filter_str = filter_str[1:].strip()

                try:
                    filter_re = re.compile(filter_str)
                except re.error as exc:
                    base_msg = f"Unable to compile regex '{filter_str}'"
                    msg = build_error_message(command_issued, base_msg)
                    raise CliError(msg) from exc

        return (command, filter_re, negate)

    def add_formatted_table(
        self,
        headers: Iterable[str],
        keys: Iterable[str],
        data: Iterable[dict[str, Any] | BaseModel],
        indent: int = 0,
    ) -> None:
        """Format and add a table of data to the output.

        Generates a table of data from the given headers, keys, and data. The
        headers are used as the column headers, and the keys are used to
        extract the data from the dicts or Pydantic models in the data list.
        The data is formatted and added to the output.

        :param headers: Column headers for the table.
        :param keys: Keys to extract data from each item in the data list.
        :param data: A list (or any sequence) of dictionaries or Pydantic models.
        :param indent: The indentation level for the table in the output.
        """
        output_data = [item.model_dump() if isinstance(item, BaseModel) else item for item in data]

        # Prepare the format string with dynamic padding based on the longest data
        raw_format = " " * indent
        for key, header in zip(keys, headers):
            longest = max(len(header), *(len(str(d[key])) for d in output_data))
            raw_format += "{:<%d}   " % longest

        # Add headers and rows to the output
        self.add_line(raw_format.format(*headers))
        for d in output_data:
            self.add_line(raw_format.format(*[str(d[key]) for key in keys]))

    def filtered_output(self) -> list[str]:
        """Return the lines of output.

        If the command is set, and it has a filter, the lines will
        be filtered by the command's filter.

        Note: This filtering is not cached, so repeated calls will
        re-filter the output (to the same result, presumably).
        """
        lines = self._output
        filter_re = self._filter_re

        if filter_re is None:
            return lines

        if self._filter_negate:
            return [line for line in lines if not filter_re.search(line)]

        return [line for line in lines if filter_re.search(line)]

    def render(self) -> None:
        """Print the output to stdout, and records it if recording is active."""
        self.recording_output()

        for line in self._ok:
            print(f"OK: {line}")

        for line in self.filtered_output():
            print(line)

    def __str__(self) -> str:
        """Return the formatted output as a single string."""
        return "\n".join(self._output)
